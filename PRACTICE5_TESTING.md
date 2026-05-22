# Проверка практики 5

Практика 5 добавляет хранение антивирусных баз на диске, проверку целостности, резервную копию и периодическое обновление баз.

## Подготовка

Запусти PowerShell от администратора в папке с exe-файлами:

```powershell
cd "C:\Users\Schur\V_US\6 семестр\ЗИОВПО\5 practice"
```

Если служба уже установлена старым путём:

```powershell
sc.exe delete ZIOVPOPracticeService
```

Создай и запусти службу:

```powershell
sc.exe create ZIOVPOPracticeService binPath= "C:\Users\Schur\V_US\6 семестр\ЗИОВПО\5 practice\ZIOVPOService.exe" start= demand
sc.exe start ZIOVPOPracticeService
sc.exe query ZIOVPOPracticeService
```

## Проверка базы на диске

После старта службы рядом с `ZIOVPOService.exe` должен появиться файл базы:

```powershell
dir .\ziovpo_avdb.bin
```

После первого периодического обновления или ручного recovery должна появиться резервная копия:

```powershell
dir .\ziovpo_avdb.bak
```

## Проверка загрузки базы в GUI

1. Открой GUI через иконку в трее.
2. Войди:

```text
login: test
password: test
```

3. Активируй лицензию:

```text
DEMO-KEY
```

Ожидаемо: в GUI отображается дата выпуска AV-базы и количество записей.

## Проверка сканирования

Создай тестовые файлы:

```powershell
New-Item -ItemType Directory -Force .\av-test
Set-Content -Encoding ASCII .\av-test\clean.txt "hello"
Set-Content -Encoding ASCII .\av-test\bad.ps1 "Write-Host ZIOVPO-SCRIPT-MALWARE"
[IO.File]::WriteAllBytes("$PWD\av-test\bad.exe", [Text.Encoding]::ASCII.GetBytes("MZ......EICAR-ZIOVPO-PE"))
```

В GUI:

```text
Folder... -> av-test -> Scan folder
```

Ожидаемо: `clean.txt` не детектится, `bad.ps1` и `bad.exe` отображаются как `INFECTED`.

## Проверка периодического обновления

Служба обновляет AV-базы раз в 60 секунд.

```powershell
Start-Sleep -Seconds 70
dir .\ziovpo_avdb.bin, .\ziovpo_avdb.bak
type .\ZIOVPOService.log | findstr /c:"AV database updated successfully"
```

Ожидаемо: есть `.bin`, есть `.bak`, в логе есть сообщение об успешном обновлении. В GUI количество записей должно стать больше после обновления.

## Проверка восстановления при повреждении основной базы

Останови службу через GUI: `Файл -> Выход` или `Выход` из меню трея.

Повреди основной файл базы:

```powershell
[byte[]]$b = [IO.File]::ReadAllBytes(".\ziovpo_avdb.bin")
$b[0] = 0
[IO.File]::WriteAllBytes(".\ziovpo_avdb.bin", $b)
sc.exe start ZIOVPOPracticeService
Start-Sleep -Seconds 3
type .\ZIOVPOService.log | findstr /c:"Primary AV database load failed" /c:"AV database restored from backup" /c:"AV database updated successfully"
```

Ожидаемо: служба не падает, а восстанавливает базу из backup или принудительно обновляет её.

## Проверка fallback на базу по умолчанию

Останови службу через GUI, затем удали файлы базы:

```powershell
del .\ziovpo_avdb.bin
del .\ziovpo_avdb.bak
sc.exe start ZIOVPOPracticeService
Start-Sleep -Seconds 3
dir .\ziovpo_avdb.bin
type .\ZIOVPOService.log | findstr /c:"creating default database" /c:"Default AV database loaded"
```

Ожидаемо: служба создаёт базу по умолчанию и продолжает работать.

## Что говорить на защите

База хранится на диске в бинарном компактном формате `ziovpo_avdb.bin`: заголовок, версия, дата выпуска, количество записей, подпись манифеста и массив AV-записей. Целостность проверяется SHA-256 подписью манифеста и SHA-256 подписью каждой записи.

При старте служба загружает базу с диска. Если основная база повреждена, служба пытается обновить её, затем восстановить из `ziovpo_avdb.bak`, а если backup отсутствует или тоже повреждён, создаёт базу по умолчанию из встроенных записей.

Периодическое обновление выполняется фоновым потоком раз в 60 секунд: перед обновлением создаётся backup, затем загружается новая база. Если новая база не проходит проверку, выполняется rollback из backup.
