# 🛡️ BugReport Checker (Web Edition)

![Build](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square&logo=github)
![Version](https://img.shields.io/badge/latest%20version-v1.3-blue?style=flat-square)
![Downloads](https://img.shields.io/github/downloads/altushkaso2/BugReportChecker/total?style=flat-square&label=downloads&color=yellow)
![Language](https://img.shields.io/badge/c++-99.5%25-555555?style=flat-square&logo=c%2B%2B)
![Platform](https://img.shields.io/badge/platform-Web%20(Wasm)-orange?style=flat-square&logo=googlechrome)

**Мощный инструмент для анализа Android через `bugreport.txt`.**

Теперь работает прямо в браузере! Все вычисления происходят локально на вашем устройстве благодаря технологии **WebAssembly**.

---

## 🌐 [ЗАПУСТИТЬ ОНЛАЙН ВЕРСИЮ](https://altushkaso2.github.io/BugReportChecker/)

*(Нажмите на ссылку выше, чтобы открыть инструмент)*

---

## 🚀 Демонстрация (Результат анализа)

После загрузки отчета вы получаете детальный анализ в современном интерфейсе:

```text
=== REPORT ANALYSIS RESULT ===

Model: Pixel 7 Pro
Android Ver: 14
Bootloader: Unlocked (orange)
Root Status: Magisk Detected

Risk Score: 9/10
Verdict: CRITICAL

[Root & Frameworks]
- Magisk property detected (Version: 27.0)
- Zygisk library loaded into a process
- Root Process: 'magiskd' detected

[Root Hiding & Evasion]
- Play Integrity Fix property detected
- TrickyStore log detected

[Anomalous System Logs]
- SELinux: Active Magisk process context detected
````

## ✨ Основные возможности

  * **⚡ Мгновенный анализ:** Использует скомпилированный C++ код прямо в браузере.
  * **🔒 100% Приватность:** Ваши файлы не покидают ваш компьютер. Анализ идет в оперативной памяти браузера.
  * **📦 Умная загрузка:** Просто перетащите `.zip` архив или `.txt` файл — программа сама найдет и распакует нужный лог.
  * **🔍 Глубокое сканирование:**
      * Поиск следов **Magisk, KernelSU, APatch**.
      * Обнаружение **Zygisk, LSPosed, Frida**.
      * Проверка статуса **Bootloader** и **SELinux**.
      * Анализ монтирования файловой системы и процессов.

## 🛠️ Сборка Web-версии (Для разработчиков)

Если вы хотите собрать проект самостоятельно из исходников:

1.  **Установите Emscripten (EMSDK):**

    ```bash
    git clone [https://github.com/emscripten-core/emsdk.git](https://github.com/emscripten-core/emsdk.git)
    cd emsdk
    ./emsdk install latest
    ./emsdk activate latest
    source ./emsdk_env.sh
    ```

2.  **Скомпилируйте проект:**

    ```bash
    # Шаг 1: Компиляция библиотеки miniz (C)
    emcc -c vendor/miniz/miniz.c -I vendor/miniz -O3 -o miniz.o

    # Шаг 2: Сборка всего проекта в WebAssembly (C++)
    em++ src/wasm_bridge.cpp src/analyzer/*.cpp src/rules/*.cpp src/platform/*.cpp miniz.o \
      -I include -I vendor/miniz \
      -o docs/bugreport.js \
      -std=c++17 -O3 --bind \
      -s WASM=1 \
      -s ALLOW_MEMORY_GROWTH=1 \
      -s FORCE_FILESYSTEM=1 \
      -s MODULARIZE=1 \
      -s EXPORT_NAME="createModule" \
      -s "EXPORTED_RUNTIME_METHODS=['FS']"
    ```

3.  **Запуск:**
    Откройте файл `docs/index.html` через локальный сервер (например, `python3 -m http.server`).

## 📄 Лицензия

Все права защищены.
Code by altushkaso2.

```
Have fun :D
```
