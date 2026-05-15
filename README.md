# ZIOVPO Practice 1: Tray Application

Графическое приложение для Windows на C++ и Win32 API.

## Возможности

- при запуске добавляет иконку в область уведомлений панели задач;
- левый клик по иконке открывает главное окно;
- правый клик по иконке открывает контекстное меню;
- контекстное меню содержит пункты `Открыть` и `Выход`;
- после пересоздания панели задач иконка добавляется повторно;
- поддерживает запуск без показа главного окна;
- при закрытии главного окна приложение продолжает работать в фоне;
- главное окно содержит меню `Файл -> Выход`;
- повторный запуск для пользователя блокируется именованным mutex;
- сборка выполняется через CMake.

## Локальная сборка

Требования:

- Windows;
- Visual Studio 2022 с компонентами C++;
- CMake 3.20 или новее.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Готовый exe:

```text
build/Release/ZIOVPOTrayApp.exe
```

## Запуск

Обычный запуск:

```powershell
.\build\Release\ZIOVPOTrayApp.exe
```

Запуск в фоновом режиме, без показа главного окна:

```powershell
.\build\Release\ZIOVPOTrayApp.exe --background
```

Также поддерживаются аргументы `--hidden`, `/background`, `/hidden`.

## CI

GitHub Actions workflow `.github/workflows/windows-build.yml` собирает проект на `windows-latest` и публикует `ZIOVPOTrayApp.exe` как артефакт сборки.
