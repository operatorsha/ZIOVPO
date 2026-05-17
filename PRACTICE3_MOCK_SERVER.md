# Проверка практики 3 без сервера 1.2

В проект добавлен тестовый сервер `ZIOVPOMockLicenseServer.exe`. Он нужен только для локальной проверки практики 3, если полноценный сервер лицензий из задания 1.2 не реализован.

Также в службе есть встроенный демонстрационный fallback: если внешний HTTP-сервер недоступен, вход `test` / `test` и активация `DEMO-KEY` выполняются локально в оперативной памяти службы. Это позволяет проверить GUI и RPC даже без запущенного mock-сервера.

Сервер поднимает HTTP API:

```text
POST /api/auth/login
POST /api/auth/refresh
GET  /api/license/status
POST /api/license/activate
```

Тестовые данные:

```text
login: test
password: test
activation code: DEMO-KEY
expired license demo code: EXPIRED-KEY
blocked license demo code: BLOCKED-KEY
```

## Запуск

Открой обычный PowerShell в папке с exe-файлами и запусти:

```powershell
.\ZIOVPOMockLicenseServer.exe
```

Окно сервера должно остаться открытым. Закрывать его нужно только после проверки.

## Настройка службы на mock-сервер

Открой PowerShell от имени администратора:

```powershell
setx ZIOVPO_API_BASE_URL "http://127.0.0.1:18080" /M
```

После этого перезапусти службу, чтобы она перечитала переменную окружения:

```powershell
sc.exe delete ZIOVPOPracticeService
sc.exe create ZIOVPOPracticeService binPath= "C:\Users\Schur\V_US\6 семестр\ЗИОВПО\3 practice\ZIOVPOService.exe" start= demand
sc.exe start ZIOVPOPracticeService
```

Если служба была помечена на удаление или не удаляется сразу, перезагрузи Windows и повтори команды.

## Проверка

1. Запусти `ZIOVPOMockLicenseServer.exe`.
2. Запусти службу `ZIOVPOPracticeService`.
3. Открой окно приложения через иконку в трее.
4. Введи логин `test` и пароль `test`.
5. Проверь, что на главном экране появился пользователь `test`.
6. Если лицензии нет, введи код `DEMO-KEY`.
7. Проверь, что появилась дата окончания лицензии и AV-функция разблокировалась.

Проверка через curl:

```powershell
curl.exe http://127.0.0.1:18080/api/license/status
curl.exe -X POST http://127.0.0.1:18080/api/auth/login -H "Content-Type: application/json" -d "{\"login\":\"test\",\"password\":\"test\"}"
curl.exe -X POST http://127.0.0.1:18080/api/license/activate -H "Content-Type: application/json" -d "{\"activationCode\":\"DEMO-KEY\"}"
curl.exe -X POST http://127.0.0.1:18080/api/license/activate -H "Content-Type: application/json" -d "{\"activationCode\":\"EXPIRED-KEY\"}"
curl.exe -X POST http://127.0.0.1:18080/api/license/activate -H "Content-Type: application/json" -d "{\"activationCode\":\"BLOCKED-KEY\"}"
```

На защите можно сказать: mock-сервер имитирует сервер из задания 1.2 для демонстрации сценариев входа, проверки лицензии и активации. Основная логика практики 3 находится в Windows-службе и GUI: служба делает HTTP-запросы, хранит токены и лицензионный тикет только в памяти и отдаёт клиенту только безопасные данные через Windows RPC.
