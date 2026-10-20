#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 /* API Windows 7 и новее: получение PID клиента и запрет удалённых подключений к каналу. */
#endif
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include <math.h>
#include <time.h>
#include <bcrypt.h>
#include "ipc_validation.h"
#include "interpolation.h"
#include "ipc_security.h"
#include "pocket_sort.h"
#include "directory_notify.h"

#define PIPE_NAME_PREFIX "\\\\.\\pipe\\Task5NamedPipe-"
#define PIPE_PROTOCOL_MAGIC UINT32_C(0xABCDEF12)
#define MAX_POINTS IPC_MAX_POINTS
#define FILE_EVENT_NAME_PREFIX "Local\\Task5FileEvent-"
#define IPC_NAME_BUFFER_SIZE 96

/*
 * Создаёт непредсказуемые имена IPC-объектов. Это мешает другому процессу
 * заранее создать объект с известным именем до запуска приложения. ACL и
 * проверка PID клиента всё равно необходимы: само имя не является средством аутентификации.
 */
static BOOL GenerateUniqueIpcNames(char *pipeName, size_t pipeNameSize,
                                   char *eventName, size_t eventNameSize)
{
    UCHAR randomBytes[16];
    char suffix[sizeof(randomBytes) * 2 + 1];
    size_t i;
    int pipeLength;
    int eventLength;

    if (pipeName == NULL || eventName == NULL) return FALSE;
    if (BCryptGenRandom(NULL, randomBytes, (ULONG)sizeof(randomBytes),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return FALSE;
    }

    for (i = 0; i < sizeof(randomBytes); ++i) {
        int written = snprintf(suffix + (i * 2), sizeof(suffix) - (i * 2),
                               "%02x", (unsigned)randomBytes[i]);
        if (written != 2) return FALSE;
    }
    suffix[sizeof(suffix) - 1] = '\0';

    pipeLength = snprintf(pipeName, pipeNameSize, "%s%s", PIPE_NAME_PREFIX, suffix);
    eventLength = snprintf(eventName, eventNameSize, "%s%s", FILE_EVENT_NAME_PREFIX, suffix);
    if (pipeLength < 0 || (size_t)pipeLength >= pipeNameSize ||
        eventLength < 0 || (size_t)eventLength >= eventNameSize) {
        pipeName[0] = '\0';
        eventName[0] = '\0';
        return FALSE;
    }
    return TRUE;
}

/* Для каждой попытки подключения создаётся новое имя канала, в том числе после отказа. */
static BOOL GenerateUniquePipeName(char *pipeName, size_t pipeNameSize)
{
    char unusedEventName[IPC_NAME_BUFFER_SIZE];
    return GenerateUniqueIpcNames(pipeName, pipeNameSize,
                                  unusedEventName, sizeof(unusedEventName));
}


/* =====================================================================
 * ПОТОК МОНИТОРИНГА ДЛЯ ПРОЦЕССА 2
 * ===================================================================== */
typedef struct FileListenerContext {
    HANDLE anonymousWritePipe;
    HANDLE stopEvent;
    const char *fileEventName;
} FileListenerContext;

DWORD WINAPI Process2FileListener(LPVOID lpParam)
{
    FileListenerContext *context = (FileListenerContext *)lpParam;
    HANDLE hAnonW;
    HANDLE hStop;
    HANDLE hEv;
    HANDLE waitHandles[2];
    DWORD waitResult;

    if (context == NULL) return 1;
    /* Копирует дескрипторы, пока контекст, принадлежащий вызывающему коду, ещё существует. */
    hAnonW = context->anonymousWritePipe;
    hStop = context->stopEvent;
    if (hAnonW == NULL || hAnonW == INVALID_HANDLE_VALUE || hStop == NULL) return 1;

    hEv = OpenEventA(SYNCHRONIZE, FALSE, context->fileEventName);
    if (hEv == NULL) return 1;

    waitHandles[0] = hStop;
    waitHandles[1] = hEv;
    for (;;) {
        waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
        if (waitResult == WAIT_OBJECT_0) break;
        if (waitResult != WAIT_OBJECT_0 + 1) break;

        DWORD attr = GetFileAttributesA("data.txt");
        const char *message = (attr == INVALID_FILE_ATTRIBUTES)
            ? "ОСТАНОВКА"
            : "ПРИОСТАНОВКА";
        DWORD bytesWritten = 0;
        DWORD messageSize = (DWORD)(strlen(message) + 1);
        if (!WriteFile(hAnonW, message, messageSize, &bytesWritten, NULL) ||
            bytesWritten != messageSize) {
            break;
        }
    }

    CloseHandle(hEv);
    return 0;
}

/* =====================================================================
 * СТРУКТУРЫ ДАННЫХ
 * ===================================================================== */

/* Тот же формат точки используется IPC-проверками из ipc_validation.h. */
typedef IpcPoint Point;

// Глобальные дескрипторы для работы анонимного канала в процессе 1
HANDLE hAnonRead = NULL;
HANDLE hAnonWrite = NULL;
HANDLE hFileEvent = NULL;
HANDLE hPauseEvent = NULL;
/* Событие сообщает, что родительскому процессу нужно остановить поток мониторинга и завершить работу. */
HANDLE hMonitorStopEvent = NULL;
static volatile LONG gShutdownRequested = 0;
//Глобальные переменные данных
Point pts[MAX_POINTS];
int count = 0;
//Глобальные переменные графического окна
Point* g_pts = NULL;
int g_count = 0;
int g_degree = 1;
static SRWLOCK gDataLock = SRWLOCK_INIT;

static BOOL MonitorStopRequested(void)
{
    if (InterlockedCompareExchange(&gShutdownRequested, 0, 0) != 0) {
        return TRUE;
    }
    return hMonitorStopEvent != NULL &&
           WaitForSingleObject(hMonitorStopEvent, 0) == WAIT_OBJECT_0;
}

static void RequestApplicationShutdown(void)
{
    InterlockedExchange(&gShutdownRequested, 1);
    if (hMonitorStopEvent != NULL) SetEvent(hMonitorStopEvent);
    /* Освобождает родительский поток, ожидающий возобновления передачи данных. */
    if (hPauseEvent != NULL) SetEvent(hPauseEvent);
}

/*
 * Считывает однозначный выбор меню, не блокируя поток навсегда в scanf().
 * Проверка _kbhit() позволяет событию остановки прервать ввод при завершении приложения.
 */
static BOOL ReadMonitorChoice(int defaultChoice, int *choice)
{
    char digit = '\0';

    if (choice == NULL) return FALSE;
    *choice = defaultChoice;
    for (;;) {
        if (MonitorStopRequested()) return FALSE;
        if (!_kbhit()) {
            Sleep(25);
            continue;
        }

        int ch = _getch();
        if (ch == '\r' || ch == '\n') {
            printf("\n");
            break;
        }
        if (ch == '\b') {
            if (digit != '\0') {
                digit = '\0';
                printf("\b \b");
            }
            continue;
        }
        if (ch >= '0' && ch <= '9') {
            digit = (char)ch;
            putchar(ch);
        }
        /* Игнорирует функциональные клавиши и все остальные символы. */
    }

    if (digit == '1' || digit == '2') {
        *choice = digit - '0';
    } else {
        printf("Некорректный выбор; используется вариант %d.\n", defaultChoice);
    }
    return TRUE;
}

/* Проверяет анонимный канал опросом, чтобы событие остановки могло прервать блокирующее чтение. */
static BOOL ReadAnonMessageWithStop(HANDLE pipe, char *buffer, DWORD capacity)
{
    if (pipe == NULL || pipe == INVALID_HANDLE_VALUE || buffer == NULL || capacity < 2) {
        return FALSE;
    }

    for (;;) {
        DWORD available = 0;
        DWORD bytesRead = 0;
        DWORD toRead;

        if (MonitorStopRequested()) return FALSE;
        if (!PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL)) return FALSE;
        if (available == 0) {
            Sleep(25);
            continue;
        }

        toRead = available < capacity - 1 ? available : capacity - 1;
        if (!ReadFile(pipe, buffer, toRead, &bytesRead, NULL) || bytesRead == 0) {
            return FALSE;
        }
        buffer[bytesRead] = '\0';
        return TRUE;
    }
}

static void CloseHandleIfOpen(HANDLE *handle)
{
    if (handle != NULL && *handle != NULL && *handle != INVALID_HANDLE_VALUE) {
        CloseHandle(*handle);
        *handle = NULL;
    }
}

/* Сигнализирует потоку мониторинга, дожидается прекращения работы с общими дескрипторами и закрывает поток. */
static void StopAndJoinMonitor(HANDLE *threadHandle)
{
    if (hMonitorStopEvent != NULL) SetEvent(hMonitorStopEvent);
    if (hPauseEvent != NULL) SetEvent(hPauseEvent);

    if (threadHandle != NULL && *threadHandle != NULL && *threadHandle != INVALID_HANDLE_VALUE) {
        WaitForSingleObject(*threadHandle, INFINITE);
        CloseHandle(*threadHandle);
        *threadHandle = NULL;
    }
    CloseHandleIfOpen(&hMonitorStopEvent);
}

/* Читает файл целиком в локальный массив, не меняя глобальное состояние при ошибке. */
static BOOL LoadPointsFromFile(const char *filePath, Point output[MAX_POINTS], int *loadedCount)
{
    FILE *file;
    int found = 0;
    int parseError = 0;
    double xValue, yValue;

    if (filePath == NULL || output == NULL || loadedCount == NULL) {
        return FALSE;
    }
    *loadedCount = 0;
    file = fopen(filePath, "r");
    if (file == NULL) {
        return FALSE;
    }

    while (found < MAX_POINTS) {
        int scanResult = fscanf(file, "%lf %lf", &xValue, &yValue);
        if (scanResult == EOF) {
            break;
        }
        if (scanResult != 2) {
            parseError = 1;
            break;
        }

        Point candidate = { xValue, yValue };
        if (ipc_valid_point(&candidate)) {
            output[found++] = candidate;
        }
    }

    if (ferror(file)) {
        parseError = 1;
    }
    fclose(file);
    *loadedCount = found;
    return !parseError && ipc_valid_point_count((uint32_t)found);
}

/* Делает согласованный снимок массива перед отправкой через IPC. */
static BOOL SnapshotCurrentPoints(Point output[MAX_POINTS], uint32_t *outCount)
{
    uint32_t currentCount;
    BOOL valid;

    if (output == NULL || outCount == NULL) {
        return FALSE;
    }
    AcquireSRWLockShared(&gDataLock);
    currentCount = (count >= 0) ? (uint32_t)count : 0u;
    valid = ipc_valid_points(pts, currentCount);
    if (valid) {
        memcpy(output, pts, sizeof(Point) * currentCount);
        *outCount = currentCount;
    }
    ReleaseSRWLockShared(&gDataLock);
    return valid;
}

static void ReplaceCurrentPoints(const Point source[MAX_POINTS], int sourceCount)
{
    if (source == NULL || !ipc_valid_point_count((uint32_t)sourceCount) ||
        !ipc_valid_points(source, (uint32_t)sourceCount)) {
        return;
    }
    AcquireSRWLockExclusive(&gDataLock);
    memcpy(pts, source, sizeof(Point) * (size_t)sourceCount);
    count = sourceCount;
    ReleaseSRWLockExclusive(&gDataLock);
}

/*
 * В этом приложении каждое поле протокола передаётся отдельным сообщением
 * именованного канала в режиме PIPE_READMODE_MESSAGE. Эти функции требуют
 * полного сообщения ожидаемого размера и не принимают частичные данные.
 */
static BOOL WritePipeMessage(HANDLE pipe, const void *buffer, DWORD size)
{
    DWORD written = 0;
    if (pipe == NULL || pipe == INVALID_HANDLE_VALUE || buffer == NULL || size == 0) {
        return FALSE;
    }
    return WriteFile(pipe, buffer, size, &written, NULL) && written == size;
}

static BOOL ReadPipeMessage(HANDLE pipe, void *buffer, DWORD expectedSize)
{
    DWORD received = 0;
    if (pipe == NULL || pipe == INVALID_HANDLE_VALUE || buffer == NULL || expectedSize == 0) {
        return FALSE;
    }
    /* Ошибка ERROR_MORE_DATA (сообщение превышает ожидаемый размер) также приводит к отказу. */
    return ReadFile(pipe, buffer, expectedSize, &received, NULL) && received == expectedSize;
}

static BOOL ReadPipeStringMessage(HANDLE pipe, char *buffer, DWORD capacity)
{
    DWORD received = 0;
    if (pipe == NULL || pipe == INVALID_HANDLE_VALUE || buffer == NULL || capacity < 2) {
        return FALSE;
    }
    if (!ReadFile(pipe, buffer, capacity, &received, NULL) || received == 0 || received > capacity) {
        return FALSE;
    }
    /* Отправитель обязан включить завершающий символ '\0' в длину сообщения. */
    return buffer[received - 1] == '\0';
}

static void StopAndCloseChild(PROCESS_INFORMATION *processInfo)
{
    if (processInfo == NULL) return;

    if (processInfo->hProcess != NULL) {
        DWORD state = WaitForSingleObject(processInfo->hProcess, 0);
        if (state != WAIT_OBJECT_0) {
            /* Принудительно завершает только дочерний процесс, который ещё не сообщил о завершении. */
            TerminateProcess(processInfo->hProcess, 1);
            WaitForSingleObject(processInfo->hProcess, INFINITE);
        }
        CloseHandle(processInfo->hProcess);
        processInfo->hProcess = NULL;
    }
    CloseHandleIfOpen(&processInfo->hThread);
}

static void CleanupParentRuntime(HANDLE *monitorThread,
                                 HANDLE *namedPipe,
                                 PROCESS_INFORMATION *childInfo)
{
    /* Поток мониторинга ещё может использовать дескрипторы события и анонимного канала. */
    StopAndJoinMonitor(monitorThread);

    /* Останавливает дочерний процесс до закрытия унаследованных им дескрипторов. */
    StopAndCloseChild(childInfo);

    if (namedPipe != NULL && *namedPipe != NULL && *namedPipe != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(*namedPipe);
        CloseHandle(*namedPipe);
        *namedPipe = INVALID_HANDLE_VALUE;
    }

    CloseHandleIfOpen(&hAnonRead);
    CloseHandleIfOpen(&hAnonWrite);
    CloseHandleIfOpen(&hFileEvent);
    CloseHandleIfOpen(&hPauseEvent);
}

/* Реализация карманной сортировки вынесена в pocket_sort.h, где её можно тестировать отдельно. */

/* Читает остаток строки без зацикливания при EOF. Возвращает 0, если поток ввода закрыт. */
static int ClearInputLine(void)
{
    int ch;
    do {
        ch = getchar();
    } while (ch != '\n' && ch != EOF);
    return ch != EOF;
}

/* =====================================================================
 * ФУНКЦИИ ХЭШИРОВАНИЯ И БЕЗОПАСНОСТИ
 * ===================================================================== */

/*
 * Функция: hash_djb2
 * Реализует алгоритм хэширования строк djb2 от Дэна Бернштейна.
 * Возвращает: 32-битное беззнаковое целое число (хэш-код).
 */
unsigned long hash_djb2(unsigned char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* Эквивалентное вычисление: hash * 33 + c. */
    }
    return hash;
}

/*
 * Функция: double_hash
 * Выполняет двойное хэширование пароля.
 * Сначала хэшируется исходный пароль, затем результат переводится в строку
 * и хэшируется повторно, что усложняет взлом радужными таблицами.
 */
unsigned long double_hash(char *password) {
    char temp[64];
    unsigned long h1 = hash_djb2((unsigned char*)password);
    sprintf(temp, "%lu", h1);
    return hash_djb2((unsigned char*)temp);
}

/*
 * Функция: input_password_hidden
 * Считывает ввод пользователя с клавиатуры без отображения символов на экране,
 * заменяя каждый нажатый символ на звездочку '*'. Обрабатывает нажатие Backspace.
 */
void input_password_hidden(char *password, int max_len) {
    int i = 0;
    char ch;
    while ((ch = _getch()) != '\r' && i < max_len - 1) {
        if (ch == '\b') {
            if (i > 0) { i--; printf("\b \b"); }
        } else {
            password[i++] = ch;
            printf("*");
        }
    }
  
    password[i] = '\0'; // Завершаем строку
    printf("\n");
}

/*
 * Функция: generate_password
 * Генерирует 4-символьный пароль на основе трех исходных слов.
 */
void generate_password(char* w1, char* w2, char* w3, char* result) {
    int len1 = strlen(w1);
    int len2 = strlen(w2);
    int len3 = strlen(w3);

    // Правило 1: Сумма количеств символов в 1 и 3 словах (остаток на 26)
    int sum = len1 + len3;
    int pos = sum;
    if (sum > 26) {
        pos = sum % 26;
        if (pos == 0) pos = 26; // Остаток 0 означает последнюю букву алфавита
    }
    result[0] = 'a' + pos - 1;

    // Правило 2: Предшествует последней букве 2-го слова. Если это 'z', записать 'z'.
    char last_w2 = w2[len2 - 1];
    if (last_w2 == 'z') {
        result[1] = 'z'; // Исключение 
    }
    else if (last_w2 == 'a') {
        result[1] = 'z'; // Обычный циклический сдвиг для первой буквы
    }
    else {
        result[1] = last_w2 - 1;
    }

    // Правило 3: Обработка третьего слова
    if (len3 % 2 != 0) {
        // Нечетное: следует за средним. Если 'z' -> 'a'
        char mid = w3[len3 / 2];
        result[2] = (mid == 'z') ? 'a' : mid + 1;
    }
    else {
        // Четное: предшествует первому из средних. Если 'a' -> 'z'
        char mid_first = w3[(len3 / 2) - 1];
        result[2] = (mid_first == 'a') ? 'z' : mid_first - 1;
    }

    // Правило 4: Следует за первым символом 1-го слова. Если 'z' -> 'a'
    char first_w1 = w1[0];
    result[3] = (first_w1 == 'z') ? 'a' : first_w1 + 1;

    result[4] = '\0';
}

/*
 * Функция: log_security_event
 * Логгирует события.
 */

void log_security_event(const char* event) {
    FILE* log = fopen("security.log", "a");
    if (log) {
        time_t now = time(NULL);
        struct tm* tm_info = localtime(&now);
        char time_str[26];
        strftime(time_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);
        fprintf(log, "[%s] PID=%lu TID=%lu - %s\n", 
                time_str, GetCurrentProcessId(), GetCurrentThreadId(), event);
        fclose(log);
    }
}



/* =====================================================================
 * ЧИСЛЕННАЯ ИНТЕРПОЛЯЦИЯ
 * ===================================================================== */

/* Решатель СЛАУ и локальная полиномиальная интерполяция вынесены в
   interpolation.h, чтобы тестировать граничные случаи отдельно от графического интерфейса Win32. */

/* =====================================================================
 * ГРАФИЧЕСКИЙ ИНТЕРФЕЙС
 * ===================================================================== */

 /*
  * Функция: GraphWndProc
  * Обработчик системных сообщений для графического окна.
  * Отвечает за отрисовку осей, координатной сетки, узлов интерполяции
  * и локальной полиномиальной кривой при получении события перерисовки.
  */
LRESULT CALLBACK GraphWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rect;
        int width;
        int height;

        if (hdc == NULL) {
            return 0;
        }
        if (!GetClientRect(hwnd, &rect)) {
            EndPaint(hwnd, &ps);
            return 0;
        }
        width = rect.right - rect.left;
        height = rect.bottom - rect.top;

        if (g_pts == NULL || g_count < 2) {
            const char *text = "Недостаточно данных для графика";
            TextOutA(hdc, 10, 10, text, (int)strlen(text));
            EndPaint(hwnd, &ps);
            return 0;
        }

        {
            double min_x = g_pts[0].x;
            double max_x = g_pts[g_count - 1].x;
            double min_y = g_pts[0].y;
            double max_y = g_pts[0].y;
            double padding_y;
            const int pad = 50;
            int plot_w;
            int plot_h;
            int i;

            for (i = 0; i < g_count; ++i) {
                if (g_pts[i].y < min_y) min_y = g_pts[i].y;
                if (g_pts[i].y > max_y) max_y = g_pts[i].y;
            }
            /* Для интерполяции координаты X должны строго возрастать.
               Не расширяйте вырожденный диапазон: это может привести к экстраполяции. */
            if (!(max_x > min_x)) {
                const char *text = "Для интерполяции нужны различные значения X";
                TextOutA(hdc, 10, 10, text, (int)strlen(text));
                EndPaint(hwnd, &ps);
                return 0;
            }
            for (i = 1; i < g_count; ++i) {
                if (g_pts[i].x <= g_pts[i - 1].x) {
                    const char *text = "Координаты X должны быть уникальными";
                    TextOutA(hdc, 10, 10, text, (int)strlen(text));
                    EndPaint(hwnd, &ps);
                    return 0;
                }
            }
            padding_y = (max_y - min_y) * 0.1;
            if (padding_y < 1e-5) padding_y = 1.0;
            min_y -= padding_y;
            max_y += padding_y;

            plot_w = width - 2 * pad;
            plot_h = height - 2 * pad;
            if (plot_w <= 0 || plot_h <= 0) {
                const char *text = "Увеличьте размер окна для графика";
                TextOutA(hdc, 10, 10, text, (int)strlen(text));
                EndPaint(hwnd, &ps);
                return 0;
            }

            /* Перед вызовом DeleteObject необходимо восстановить прежние объекты, выбранные в контексте устройства GDI. */
            {
                HPEN axisPen = CreatePen(PS_SOLID, 2, RGB(100, 100, 100));
                if (axisPen != NULL) {
                    HGDIOBJ oldPen = SelectObject(hdc, axisPen);
                    if (oldPen != NULL && oldPen != HGDI_ERROR) {
                        MoveToEx(hdc, pad, height - pad, NULL);
                        LineTo(hdc, width - pad, height - pad);
                        MoveToEx(hdc, pad, pad, NULL);
                        LineTo(hdc, pad, height - pad);
                        SelectObject(hdc, oldPen);
                    }
                    DeleteObject(axisPen);
                }
            }

            {
                HPEN linePen = CreatePen(PS_SOLID, 2, RGB(0, 0, 200));
                if (linePen != NULL) {
                    HGDIOBJ oldPen = SelectObject(hdc, linePen);
                    if (oldPen != NULL && oldPen != HGDI_ERROR) {
                        int firstPoint = 1;
                        int px;
                        for (px = 0; px <= plot_w; ++px) {
                            double real_x = min_x + (max_x - min_x) * ((double)px / plot_w);
                            double real_y;
                            int py;
                            if (!ipc_interpolate_point(g_pts, (size_t)g_count, real_x,
                                                       g_degree, &real_y) ||
                                !IPC_ISFINITE(real_y)) {
                                /* После численно неустойчивой точки начинается новый сегмент кривой. */
                                firstPoint = 1;
                                continue;
                            }
                            /* Ограничивает значение перед преобразованием числа с плавающей точкой в целое, чтобы избежать переполнения. */
                            if (real_y <= min_y) {
                                py = height - pad;
                            } else if (real_y >= max_y) {
                                py = pad;
                            } else {
                                double pixelY = height - pad -
                                    ((real_y - min_y) / (max_y - min_y) * plot_h);
                                if (pixelY < pad) pixelY = pad;
                                if (pixelY > height - pad) pixelY = height - pad;
                                py = (int)pixelY;
                            }
                            if (firstPoint) {
                                MoveToEx(hdc, pad + px, py, NULL);
                                firstPoint = 0;
                            } else {
                                LineTo(hdc, pad + px, py);
                            }
                        }
                        SelectObject(hdc, oldPen);
                    }
                    DeleteObject(linePen);
                }
            }

            {
                HBRUSH pointBrush = CreateSolidBrush(RGB(200, 0, 0));
                if (pointBrush != NULL) {
                    HGDIOBJ oldBrush = SelectObject(hdc, pointBrush);
                    if (oldBrush != NULL && oldBrush != HGDI_ERROR) {
                        for (i = 0; i < g_count; ++i) {
                            int px = pad + (int)((g_pts[i].x - min_x) / (max_x - min_x) * plot_w);
                            int py = height - pad - (int)((g_pts[i].y - min_y) / (max_y - min_y) * plot_h);
                            Ellipse(hdc, px - 4, py - 4, px + 4, py + 4);
                        }
                        SelectObject(hdc, oldBrush);
                    }
                    DeleteObject(pointBrush);
                }
            }
        }

        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcA(hwnd, msg, wParam, lParam);
    }
}

void ShowGraphWindow(Point* pts, int count, int degree)
{
    HINSTANCE hInstance = GetModuleHandleA(NULL);
    WNDCLASSA wc;
    HWND hwnd = NULL;
    char title[200];
    int titleLength;
    MSG msg;
    BOOL classRegistered = FALSE;

    if (pts == NULL || count < 2 || count > (int)MAX_POINTS || degree < 1 || degree > 10) {
        fprintf(stderr, "[Ошибка] Некорректные параметры графика.\n");
        return;
    }
    g_pts = pts;
    g_count = count;
    g_degree = degree;

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = GraphWndProc;
    wc.hInstance = hInstance;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "InterpolationGraphClass";
    if (!RegisterClassA(&wc)) {
        fprintf(stderr, "[Ошибка] RegisterClass завершился с кодом %lu.\n", GetLastError());
        g_pts = NULL;
        g_count = 0;
        return;
    }
    classRegistered = TRUE;

    titleLength = snprintf(title, sizeof(title),
        "График интерполяции (Порядок: %d) | PID: %lu | TID: %lu",
        degree, GetCurrentProcessId(), GetCurrentThreadId());
    if (titleLength < 0 || (size_t)titleLength >= sizeof(title)) {
        fprintf(stderr, "[Ошибка] Не удалось сформировать заголовок окна.\n");
        goto graph_cleanup;
    }

    hwnd = CreateWindowExA(0, "InterpolationGraphClass", title,
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
        NULL, NULL, hInstance, NULL);
    if (hwnd == NULL) {
        fprintf(stderr, "[Ошибка] CreateWindowEx завершился с кодом %lu.\n", GetLastError());
        goto graph_cleanup;
    }

    printf("\n[Система | PID: %lu] Графическое окно открыто; закройте его для продолжения.\n",
           GetCurrentProcessId());
    for (;;) {
        BOOL getMessageResult = GetMessageA(&msg, NULL, 0, 0);
        if (getMessageResult == 0) break;
        if (getMessageResult == -1) {
            fprintf(stderr, "[Ошибка] GetMessage завершился с кодом %lu.\n", GetLastError());
            break;
        }
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

graph_cleanup:
    if (hwnd != NULL && IsWindow(hwnd)) {
        DestroyWindow(hwnd);
    }
    if (classRegistered) {
        UnregisterClassA("InterpolationGraphClass", hInstance);
    }
    g_pts = NULL;
    g_count = 0;
}

/* =====================================================================
 * ПОТОКИ И МЕЖПРОЦЕССНОЕ ВЗАИМОДЕЙСТВИЕ
 * ===================================================================== */

static BOOL BeginDirectoryChangeRead(HANDLE directory, HANDLE notificationEvent,
                                     OVERLAPPED *overlapped, BYTE *buffer, DWORD capacity)
{
    DWORD flags = FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME |
                  FILE_NOTIFY_CHANGE_SIZE;

    if (!ResetEvent(notificationEvent)) return FALSE;
    ZeroMemory(overlapped, sizeof(*overlapped));
    overlapped->hEvent = notificationEvent;
    if (ReadDirectoryChangesW(directory, buffer, capacity, FALSE, flags,
                              NULL, overlapped, NULL)) {
        return TRUE;
    }
    return GetLastError() == ERROR_IO_PENDING;
}

/* Отслеживает только изменения data.txt и сохраняет активным асинхронное наблюдение во время запросов пользователю. */
DWORD WINAPI FileMonitorThread(LPVOID lpParam)
{
    HANDLE directory = INVALID_HANDLE_VALUE;
    HANDLE notificationEvent = NULL;
    HANDLE waitHandles[2];
    OVERLAPPED overlapped;
    union DirectoryNotificationBuffer {
        DWORD alignment;
        BYTE bytes[4096];
    } notificationBuffer;
    BOOL readPending = FALSE;
    DWORD resultCode = 0;
    (void)lpParam;

    directory = CreateFileA(".", FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    if (directory == INVALID_HANDLE_VALUE) {
        printf("[Ошибка] Не удалось открыть каталог для мониторинга (код %lu).\n", GetLastError());
        if (hPauseEvent != NULL) SetEvent(hPauseEvent);
        return 1;
    }
    notificationEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (notificationEvent == NULL) {
        printf("[Ошибка] Не удалось создать событие файлового мониторинга (код %lu).\n", GetLastError());
        CloseHandle(directory);
        if (hPauseEvent != NULL) SetEvent(hPauseEvent);
        return 1;
    }
    if (hMonitorStopEvent == NULL) {
        CloseHandle(notificationEvent);
        CloseHandle(directory);
        if (hPauseEvent != NULL) SetEvent(hPauseEvent);
        return 1;
    }

    waitHandles[0] = hMonitorStopEvent;
    waitHandles[1] = notificationEvent;
    if (!BeginDirectoryChangeRead(directory, notificationEvent, &overlapped,
                                  notificationBuffer.bytes, (DWORD)sizeof(notificationBuffer.bytes))) {
        printf("[Ошибка] ReadDirectoryChangesW завершился с кодом %lu.\n", GetLastError());
        resultCode = 1;
        goto monitor_cleanup;
    }
    readPending = TRUE;

    for (;;) {
        DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
        DWORD bytesReturned = 0;
        BOOL completed;
        BOOL dataTxtChanged = FALSE;

        if (waitResult == WAIT_OBJECT_0 || MonitorStopRequested()) break;
        if (waitResult != WAIT_OBJECT_0 + 1) {
            printf("[Ошибка] Ожидание файловых изменений завершилось с кодом %lu.\n", GetLastError());
            resultCode = 1;
            break;
        }

        completed = GetOverlappedResult(directory, &overlapped, &bytesReturned, FALSE);
        readPending = FALSE;
        if (completed) {
            dataTxtChanged = ipc_directory_batch_touches_data_txt(notificationBuffer.bytes, bytesReturned);
        } else {
            DWORD ioError = GetLastError();
            if (ioError == ERROR_NOTIFY_ENUM_DIR) {
                /* При переполнении системного буфера уведомлений осторожно перечитывает data.txt. */
                dataTxtChanged = TRUE;
            } else if (ioError == ERROR_OPERATION_ABORTED && MonitorStopRequested()) {
                break;
            } else {
                printf("[Ошибка] Чтение уведомления каталога завершилось с кодом %lu.\n", ioError);
                resultCode = 1;
                break;
            }
        }

        if (MonitorStopRequested()) break;
        if (!BeginDirectoryChangeRead(directory, notificationEvent, &overlapped,
                                      notificationBuffer.bytes, (DWORD)sizeof(notificationBuffer.bytes))) {
            printf("[Ошибка] Не удалось повторно включить файловый мониторинг (код %lu).\n", GetLastError());
            resultCode = 1;
            break;
        }
        readPending = TRUE;
        if (!dataTxtChanged) continue;

        /* Объединяет серию уведомлений от редактора при сохранении файла, не оставляя каталог без наблюдения. */
        {
            DWORD debounceStart = GetTickCount();
            for (;;) {
                DWORD elapsed = GetTickCount() - debounceStart;
                DWORD remaining;
                DWORD debounceWait;
                DWORD extraBytes = 0;
                BOOL extraCompleted;
                BOOL extraDataChange = FALSE;

                if (elapsed >= 300) break;
                remaining = 300 - elapsed;
                debounceWait = WaitForMultipleObjects(2, waitHandles, FALSE, remaining);
                if (debounceWait == WAIT_OBJECT_0 || MonitorStopRequested()) goto monitor_cleanup;
                if (debounceWait == WAIT_TIMEOUT) break;
                if (debounceWait != WAIT_OBJECT_0 + 1) {
                    printf("[Ошибка] Ожидание файлового события завершилось с кодом %lu.\n", GetLastError());
                    resultCode = 1;
                    goto monitor_cleanup;
                }

                extraCompleted = GetOverlappedResult(directory, &overlapped, &extraBytes, FALSE);
                readPending = FALSE;
                if (extraCompleted) {
                    extraDataChange = ipc_directory_batch_touches_data_txt(notificationBuffer.bytes, extraBytes);
                } else {
                    DWORD ioError = GetLastError();
                    if (ioError == ERROR_NOTIFY_ENUM_DIR) extraDataChange = TRUE;
                    else if (ioError == ERROR_OPERATION_ABORTED && MonitorStopRequested()) goto monitor_cleanup;
                    else {
                        printf("[Ошибка] Чтение уведомления каталога завершилось с кодом %lu.\n", ioError);
                        resultCode = 1;
                        goto monitor_cleanup;
                    }
                }

                if (MonitorStopRequested()) goto monitor_cleanup;
                if (!BeginDirectoryChangeRead(directory, notificationEvent, &overlapped,
                                              notificationBuffer.bytes, (DWORD)sizeof(notificationBuffer.bytes))) {
                    printf("[Ошибка] Не удалось повторно включить файловый мониторинг (код %lu).\n", GetLastError());
                    resultCode = 1;
                    goto monitor_cleanup;
                }
                readPending = TRUE;
                if (extraDataChange) debounceStart = GetTickCount();
            }
        }

        if (hPauseEvent != NULL && !ResetEvent(hPauseEvent)) {
            printf("[Ошибка] Не удалось приостановить передачу данных (код %lu).\n", GetLastError());
            resultCode = 1;
            break;
        }
        if (hFileEvent == NULL || !SetEvent(hFileEvent)) {
            printf("[Ошибка] Не удалось уведомить дочерний процесс (код %lu).\n", GetLastError());
            if (hPauseEvent != NULL) SetEvent(hPauseEvent);
            resultCode = 1;
            break;
        }

        {
            char anonBuf[50] = { 0 };
            if (!ReadAnonMessageWithStop(hAnonRead, anonBuf, (DWORD)sizeof(anonBuf))) {
                if (!MonitorStopRequested()) {
                    printf("[Предупреждение] Не удалось получить уведомление от процесса 2.\n");
                    resultCode = 1;
                }
                break;
            }
            printf("\n[МОНИТОР | PID: %lu | TID: %lu] Сигнал от процесса 2: <<%s>>\n",
                   GetCurrentProcessId(), GetCurrentThreadId(), anonBuf);
        }

        if (GetFileAttributesA("data.txt") == INVALID_FILE_ATTRIBUTES) {
            printf("\n[МОНИТОР] Файл data.txt удалён.\n1 - Завершить приложение\n2 - Дождаться восстановления\nВаш выбор: ");
            {
                int choice = 2;
                if (!ReadMonitorChoice(2, &choice)) break;
                if (choice == 1) {
                    RequestApplicationShutdown();
                    break;
                }
            }
            printf("[МОНИТОР] Ожидание файла data.txt...\n");
            while (GetFileAttributesA("data.txt") == INVALID_FILE_ATTRIBUTES) {
                if (WaitForSingleObject(hMonitorStopEvent, 500) == WAIT_OBJECT_0) break;
            }
            if (MonitorStopRequested()) break;
            {
                Point updatedPoints[MAX_POINTS];
                int updatedCount = 0;
                if (LoadPointsFromFile("data.txt", updatedPoints, &updatedCount)) {
                    ReplaceCurrentPoints(updatedPoints, updatedCount);
                    printf("[МОНИТОР] Загружено %d точек из восстановленного файла.\n", updatedCount);
                } else {
                    printf("[Предупреждение] Новый файл не прошёл проверку; прежние данные сохранены.\n");
                }
            }
        } else {
            printf("\n[МОНИТОР] Файл data.txt изменён.\n1 - Обновить данные динамически\n2 - Игнорировать изменения\nВаш выбор: ");
            {
                int choice = 2;
                if (!ReadMonitorChoice(2, &choice)) break;
                if (choice == 1) {
                    Point updatedPoints[MAX_POINTS];
                    int updatedCount = 0;
                    if (LoadPointsFromFile("data.txt", updatedPoints, &updatedCount)) {
                        ReplaceCurrentPoints(updatedPoints, updatedCount);
                        printf("[МОНИТОР] Успешно загружено %d новых точек.\n", updatedCount);
                    } else {
                        printf("[Предупреждение] Новый файл не прошёл проверку; прежние данные сохранены.\n");
                    }
                } else {
                    printf("[МОНИТОР] Изменения проигнорированы.\n");
                }
            }
        }

        if (hPauseEvent != NULL) SetEvent(hPauseEvent);
        if (MonitorStopRequested()) break;
    }

monitor_cleanup:
    if (readPending && directory != INVALID_HANDLE_VALUE) {
        DWORD ignoredBytes = 0;
        CancelIoEx(directory, &overlapped);
        GetOverlappedResult(directory, &overlapped, &ignoredBytes, TRUE);
    }
    if (hPauseEvent != NULL) SetEvent(hPauseEvent);
    CloseHandleIfOpen(&notificationEvent);
    if (directory != INVALID_HANDLE_VALUE) CloseHandle(directory);
    return resultCode;
}

/*
 * Функция: RunProcess2 (Дочерний процесс)
 * Точка входа для процесса 2. Подключается к Pipe, получает несортированные данные,
 * отправляет уведомление, выполняет карманную сортировку, строит график 
 * и отправляет результаты обратно родительскому процессу.
 */
void RunProcess2(HANDLE hAnonW, const char *pipeName, const char *fileEventName)
{
    HANDLE listenerStopEvent = NULL;
    HANDLE listenerThread = NULL;
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    FileListenerContext listenerContext;
    DWORD connectStart = GetTickCount();
    int processResult = 1;

    listenerContext.anonymousWritePipe = hAnonW;
    listenerContext.stopEvent = NULL;
    listenerContext.fileEventName = fileEventName;
    if (pipeName == NULL || fileEventName == NULL ||
        strncmp(pipeName, PIPE_NAME_PREFIX, strlen(PIPE_NAME_PREFIX)) != 0 ||
        strncmp(fileEventName, FILE_EVENT_NAME_PREFIX, strlen(FILE_EVENT_NAME_PREFIX)) != 0) {
        fprintf(stderr, "[Ошибка] Не переданы корректные имена IPC-объектов.\n");
        if (hAnonW != NULL && hAnonW != INVALID_HANDLE_VALUE) CloseHandle(hAnonW);
        return;
    }
    printf("[Процесс 2 | PID: %lu | TID: %lu] Инициализация клиента...\n",
           GetCurrentProcessId(), GetCurrentThreadId());

    if (hAnonW != NULL && hAnonW != INVALID_HANDLE_VALUE) {
        listenerStopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
        if (listenerStopEvent != NULL) {
            listenerContext.stopEvent = listenerStopEvent;
            listenerThread = CreateThread(NULL, 0, Process2FileListener,
                                          (LPVOID)&listenerContext, 0, NULL);
            if (listenerThread == NULL) {
                printf("[Предупреждение] Не удалось запустить поток мониторинга файла (ошибка %lu).\n",
                       GetLastError());
                CloseHandle(listenerStopEvent);
                listenerStopEvent = NULL;
                listenerContext.stopEvent = NULL;
            }
        } else {
            printf("[Предупреждение] Не удалось создать событие остановки потока (ошибка %lu).\n",
                   GetLastError());
        }
    }

    for (;;) {
        hPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                            OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) break;

        DWORD openError = GetLastError();
        if (openError == ERROR_PIPE_BUSY) {
            WaitNamedPipeA(pipeName, 1000);
        } else if (openError != ERROR_FILE_NOT_FOUND) {
            printf("[Ошибка] Не удалось открыть именованный канал (код %lu).\n", openError);
            goto process2_cleanup;
        }
        if (GetTickCount() - connectStart > 30000u) {
            printf("[Ошибка] Тайм-аут ожидания именованного канала.\n");
            goto process2_cleanup;
        }
        Sleep(100);
    }

    DWORD readMode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(hPipe, &readMode, NULL, NULL)) {
        printf("[Ошибка] Не удалось включить режим чтения сообщениями (код %lu).\n", GetLastError());
        goto process2_cleanup;
    }

    uint32_t protocolMagic = 0;
    uint32_t wireCount = 0;
    Point receivedPoints[MAX_POINTS];
    if (!ReadPipeMessage(hPipe, &protocolMagic, (DWORD)sizeof(protocolMagic)) ||
        protocolMagic != PIPE_PROTOCOL_MAGIC ||
        !ReadPipeMessage(hPipe, &wireCount, (DWORD)sizeof(wireCount)) ||
        !ipc_valid_point_count(wireCount)) {
        printf("[Ошибка] Некорректный заголовок или количество точек в IPC-сообщении.\n");
        goto process2_cleanup;
    }

    /* wireCount проверяется до вычисления количества байтов и чтения данных. */
    DWORD pointsMessageSize = (DWORD)(sizeof(Point) * wireCount);
    if (!ReadPipeMessage(hPipe, receivedPoints, pointsMessageSize) ||
        !ipc_valid_points(receivedPoints, wireCount)) {
        printf("[Ошибка] Размер сообщения или координаты не прошли проверку.\n");
        goto process2_cleanup;
    }

    int count = (int)wireCount;
    Point pts[MAX_POINTS];
    memcpy(pts, receivedPoints, sizeof(Point) * wireCount);

    const char msg[] = "УСПЕХ: данные получены и прошли проверку формата.";
    if (!WritePipeMessage(hPipe, msg, (DWORD)sizeof(msg))) {
        printf("[Ошибка] Не удалось отправить подтверждение приёма.\n");
        goto process2_cleanup;
    }

    if (!ipc_pocket_sort(pts, (size_t)count)) {
        printf("[Ошибка] Не удалось отсортировать точки: некорректные данные или нехватка памяти.\n");
        goto process2_cleanup;
    }

    int degree = 3;
    int is_valid = 0;
    while (!is_valid) {
        printf("\n[Процесс 2 | PID: %lu | TID: %lu] Введите порядок интерполяции (от 1 до 10): ",
               GetCurrentProcessId(), GetCurrentThreadId());
        if (scanf("%d", &degree) == 1) {
            if (degree >= 1 && degree <= 10) {
                is_valid = 1;
            } else {
                printf("[Ошибка] Порядок должен быть от 1 до 10. Попробуйте снова.\n");
            }
        } else {
            int ch;
            printf("[Ошибка] Введите целое число.\n");
            do { ch = getchar(); } while (ch != '\n' && ch != EOF);
            if (ch == EOF) goto process2_cleanup;
        }
    }

    ShowGraphWindow(pts, count, degree);

    /* Маркер протокола не является цифровой подписью и не обеспечивает криптографическую проверку целостности. */
    if (!WritePipeMessage(hPipe, &protocolMagic, (DWORD)sizeof(protocolMagic)) ||
        !WritePipeMessage(hPipe, pts, pointsMessageSize)) {
        printf("[Ошибка] Не удалось передать результат родительскому процессу.\n");
        goto process2_cleanup;
    }

    system("pause");
    processResult = 0;

process2_cleanup:
    /* Останавливает поток-слушатель и дожидается его завершения до закрытия дескриптора анонимного канала. */
    if (listenerStopEvent != NULL) SetEvent(listenerStopEvent);
    if (listenerThread != NULL) {
        WaitForSingleObject(listenerThread, INFINITE);
        CloseHandle(listenerThread);
        listenerThread = NULL;
    }
    CloseHandleIfOpen(&listenerStopEvent);
    if (hPipe != NULL && hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
        hPipe = INVALID_HANDLE_VALUE;
    }
    if (hAnonW != NULL && hAnonW != INVALID_HANDLE_VALUE) CloseHandle(hAnonW);
    if (processResult != 0) {
        printf("[Процесс 2] Завершение после ошибки или тайм-аута.\n");
    }
}

/*
 * Функция: RunProcess3 (Процесс-атакующий)
 * Бесконечно пытается открыть и тут же закрыть пайп, симулируя
 * атаку на отказ в обслуживании (DoS), 
 * исчерпывая ресурсы каналов ввода-вывода.
 */
void RunProcess3(const char *pipeName) {
    if (pipeName == NULL ||
        strncmp(pipeName, PIPE_NAME_PREFIX, strlen(PIPE_NAME_PREFIX)) != 0) {
        fprintf(stderr, "Использование: app.exe PROC3 \"\\\\.\\pipe\\Task5NamedPipe-<nonce>\" (имя печатается приложением).\n");
        return;
    }
    printf("[Процесс 3 | PID: %lu | TID: %lu] Конкурирующие подключения к %s...\n",
           GetCurrentProcessId(), GetCurrentThreadId(), pipeName);
    for (;;) {
        HANDLE hPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE,
                                   0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) CloseHandle(hPipe);
        Sleep(1); /* Учебный имитатор не должен бесконечно загружать ядро процессора активным циклом. */
    }
}

/*
 * Функция: check_and_prepare_word
 * Проверяет, состоит ли слово только из латинских букв.
 * Автоматически переводит заглавные буквы в строчные (a-z).
 * Возвращает 1 (успех) или 0 (ошибка, найдены другие символы).
 */
int check_and_prepare_word(char* word) {
    if (word == NULL || strlen(word) == 0) return 0;

    for (int i = 0; word[i] != '\0'; i++) {
        // Перевод заглавных латинских букв в строчные
        if (word[i] >= 'A' && word[i] <= 'Z') {
            word[i] = word[i] + ('a' - 'A');
        }
        // Если символ не является строчной латинской буквой — это ошибка
        else if (!(word[i] >= 'a' && word[i] <= 'z')) {
            return 0;
        }
    }
    return 1;
}

/* =====================================================================
 * ГЛАВНАЯ ФУНКЦИЯ (ПРОЦЕСС 1 - РОДИТЕЛЬСКИЙ)
 * ===================================================================== */

int main(int argc, char *argv[]) {
    HANDLE monitorThread = NULL;
    HANDLE hNamedPipe = INVALID_HANDLE_VALUE;
    PROCESS_INFORMATION pi;
    int exitCode = 1;
    BOOL pipe_connected = FALSE;
    char pipeName[IPC_NAME_BUFFER_SIZE] = { 0 };
    char fileEventName[IPC_NAME_BUFFER_SIZE] = { 0 };
    ZeroMemory(&pi, sizeof(pi));

    // Настройка кодировки консоли для поддержки кириллицы
    SetConsoleOutputCP(CP_UTF8); 
    SetConsoleCP(CP_UTF8);

    // Диспетчеризация процессов. Если запущен с флагом PROC2/PROC3 - уходим в ветвление
    if (argc > 1) {
        if (strcmp(argv[1], "PROC2") == 0) {
            HANDLE hAnonW = NULL;
            void *rawHandle = NULL;
            /* Значение HANDLE передаётся только от родителя через унаследованный дескриптор. */
            if (argc <= 2 || sscanf(argv[2], "%p", &rawHandle) != 1 || rawHandle == NULL) {
                fprintf(stderr, "[Ошибка] Не передан корректный унаследованный дескриптор.\n");
                return 2;
            }
            if (argc < 5) {
                fprintf(stderr, "[Ошибка] Для PROC2 нужны имя канала и имя события.\n");
                return 2;
            }
            hAnonW = (HANDLE)rawHandle;
            RunProcess2(hAnonW, argv[3], argv[4]);
            return 0;
        }
        if (strcmp(argv[1], "PROC3") == 0) {
            RunProcess3(argc > 2 ? argv[2] : NULL);
            return 0;
        }
    }

    log_security_event("Приложение запущено");

    // --- БЛОК 1: ИДЕНТИФИКАЦИЯ И АУТЕНТИФИКАЦИЯ ---
    char login[50] = "admin", w1[50], w2[50], w3[50], gen_pwd[5];
    int acc = 0;

    printf("=== РЕГИСТРАЦИЯ ===\n");
    while (!acc) {
        printf("Введите три слова (только латинские буквы): ");

        // Считываем три слова. Если успешно, проверяем их содержимое
        if (scanf("%49s %49s %49s", w1, w2, w3) == 3) {

            // Если все три слова состоят только из латиницы
            if (check_and_prepare_word(w1) && check_and_prepare_word(w2) && check_and_prepare_word(w3)) {

                generate_password(w1, w2, w3, gen_pwd);
                printf("Сгенерированный пароль: %s\nОценка криптостойкости: Низкая\nПринять? (1-Да, 0-Нет): ", gen_pwd);

                // Проверка корректности ввода ответа (1 или 0)
                if (scanf("%d", &acc) != 1 || (acc != 0 && acc != 1)) {
                    acc = 0;
                    if (!ClearInputLine()) {
                        printf("[Ошибка] Поток ввода закрыт.\n");
                        return 1;
                    }
                }
            }
            else {
                printf("[Ошибка] Слова должны состоять исключительно из букв латинского алфавита (A-Z, a-z). Никаких цифр или кириллицы!\n\n");
                if (!ClearInputLine()) return 1; // Очистка до конца строки, без зацикливания на EOF
            }
        }
        else {
            printf("[Ошибка] Ожидался ввод ровно трех слов.\n\n");
            if (!ClearInputLine()) return 1; // Очистка до конца строки, без зацикливания на EOF
        }
    }

    // Сохраняем эталонный хэш-код пароля
    unsigned long saved_hash = double_hash(gen_pwd);

    int attempts = 0;
    const int MAX_ATTEMPTS = 5;
    const int BLOCK_TIME_SEC = 30;
    printf("\n=== ВХОД ===\nЛогин: ");
    char in_log[50], in_pwd[50];
    if (scanf("%49s", in_log) != 1) {
        printf("[Ошибка] Не удалось прочитать логин.\n");
        log_security_event("Ошибка чтения логина");
        return 1;
    }
    if (strcmp(in_log, login) != 0) {
        printf("[Ошибка] Неверный логин.\n");
        log_security_event("Отклонён неверный логин");
        return 1;
    }

    while (attempts < MAX_ATTEMPTS) {
        printf("Пароль: ");
        input_password_hidden(in_pwd, sizeof(in_pwd));
        if (double_hash(in_pwd) == saved_hash) {
            printf("Аутентификация пройдена!\n\n");
            log_security_event("Аутентификация успешна");
            break;
        } else {
            attempts++;
            printf("Неверный пароль. Осталось попыток: %d\n", MAX_ATTEMPTS - attempts);
            if (attempts >= MAX_ATTEMPTS) {
                printf("Превышено число попыток. Блокировка на %d секунд.\n", BLOCK_TIME_SEC);
                Sleep(BLOCK_TIME_SEC * 1000);
                return 1;
            }
        }
    }

    // --- БЛОК 2: ЧТЕНИЕ ДАННЫХ ИЗ ФАЙЛА ---
    if (!LoadPointsFromFile("data.txt", pts, &count)) {
        printf("Ошибка: data.txt должен содержать корректные пары координат; допустимо от 2 до %u точек.\n", (unsigned)MAX_POINTS);
        return 1;
    }
    printf("[Процесс 1 | PID: %lu | TID: %lu] Считано %d координат.\n", GetCurrentProcessId(), GetCurrentThreadId(), count);

    if (!GenerateUniqueIpcNames(pipeName, sizeof(pipeName), fileEventName, sizeof(fileEventName))) {
        printf("Ошибка генерации уникальных имён IPC-объектов.\n");
        return 1;
    }
    // Настройка структуры безопасности для наследования дескрипторов дочерним процессом
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    if (!CreatePipe(&hAnonRead, &hAnonWrite, &sa, 0)) {
        printf("Ошибка создания анонимного канала.\n");
        goto parent_cleanup;
    }
    // Запрещаем дочерним процессам наследовать дескриптор чтения родителя.
    if (!SetHandleInformation(hAnonRead, HANDLE_FLAG_INHERIT, 0)) {
        printf("Ошибка настройки наследования дескриптора (код %lu).\n", GetLastError());
        goto parent_cleanup;
    }

    // Для общих IPC-объектов задаётся явная DACL владельца и SYSTEM без широкого разрешения для Everyone.
    PSECURITY_DESCRIPTOR eventSecurityDescriptor = NULL;
    SECURITY_ATTRIBUTES eventSecurityAttributes;
    if (!IpcCreateRestrictedSecurityAttributes(&eventSecurityAttributes, &eventSecurityDescriptor)) {
        printf("Ошибка подготовки ACL события IPC (код %lu).\n", GetLastError());
        goto parent_cleanup;
    }
    SetLastError(ERROR_SUCCESS);
    hFileEvent = CreateEventA(&eventSecurityAttributes, FALSE, FALSE, fileEventName);
    DWORD fileEventCreateStatus = GetLastError();
    IpcFreeSecurityDescriptor(&eventSecurityDescriptor);
    if (hFileEvent != NULL && fileEventCreateStatus == ERROR_ALREADY_EXISTS) {
        CloseHandle(hFileEvent);
        hFileEvent = NULL;
        printf("Обнаружен уже существующий объект события IPC; отказ от запуска.\n");
        goto parent_cleanup;
    }
    hPauseEvent = CreateEventA(NULL, TRUE, TRUE, NULL);
    hMonitorStopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (hFileEvent == NULL || hPauseEvent == NULL || hMonitorStopEvent == NULL) {
        printf("Ошибка создания событий синхронизации (код %lu).\n", GetLastError());
        goto parent_cleanup;
    }

    /* Сохраняет дескриптор потока: при очистке нужно остановить мониторинг и дождаться его завершения до закрытия общих дескрипторов. */
    monitorThread = CreateThread(NULL, 0, FileMonitorThread, NULL, 0, NULL);
    if (monitorThread == NULL) {
        printf("Ошибка запуска потока мониторинга (код %lu).\n", GetLastError());
        goto parent_cleanup;
    }

    // --- БЛОК 3: IPC с проверкой PID и валидацией сообщений ---
    STARTUPINFOA si;
    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    char executablePath[MAX_PATH];
    DWORD executablePathLength = GetModuleFileNameA(NULL, executablePath, MAX_PATH);
    if (executablePathLength == 0 || executablePathLength >= MAX_PATH) {
        printf("[Ошибка] Не удалось определить путь исполняемого файла (код %lu).\n", GetLastError());
        goto parent_cleanup;
    }

    uint32_t protocolMagic = PIPE_PROTOCOL_MAGIC;
    uint32_t wireCount = 0;
    Point pointsToSend[MAX_POINTS];

    while (!pipe_connected && !MonitorStopRequested()) {
        /* После неудачного или отклонённого подключения генерируется новое, непредсказуемое имя объекта. */
        if (!GenerateUniquePipeName(pipeName, sizeof(pipeName))) {
            printf("[Ошибка] Не удалось обновить имя именованного канала.\n");
            goto parent_cleanup;
        }
        PSECURITY_DESCRIPTOR pipeSecurityDescriptor = NULL;
        SECURITY_ATTRIBUTES pipeSecurityAttributes;
        if (!IpcCreateRestrictedSecurityAttributes(&pipeSecurityAttributes, &pipeSecurityDescriptor)) {
            printf("[Ошибка] Не удалось подготовить ACL именованного канала (код %lu).\n", GetLastError());
            goto parent_cleanup;
        }
        hNamedPipe = CreateNamedPipeA(
            pipeName,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1, 4096, 4096, 0, &pipeSecurityAttributes);
        DWORD pipeCreateStatus = GetLastError();
        IpcFreeSecurityDescriptor(&pipeSecurityDescriptor);
        if (hNamedPipe == INVALID_HANDLE_VALUE) {
            printf("[Ошибка] CreateNamedPipe завершился с кодом %lu.\n", pipeCreateStatus);
            goto parent_cleanup;
        }
        /* Печатает имя только после создания системного объекта с заданной DACL. */
        printf("[IPC] Имя канала текущей попытки (для локального теста PROC3): %s\n", pipeName);

        char cmdLine[MAX_PATH + 256];
        int commandLength = snprintf(cmdLine, sizeof(cmdLine), "\"%s\" PROC2 %p \"%s\" \"%s\"", executablePath, (void *)hAnonWrite, pipeName, fileEventName);
        if (commandLength < 0 || (size_t)commandLength >= sizeof(cmdLine)) {
            printf("[Ошибка] Командная строка дочернего процесса слишком длинная.\n");
            goto parent_cleanup;
        }

        ZeroMemory(&pi, sizeof(pi));
        if (!CreateProcessA(executablePath, cmdLine, NULL, NULL, TRUE,
                            CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
            DWORD createError = GetLastError();
            printf("[Ошибка] Не удалось запустить процесс 2 (код %lu).\n", createError);
            goto parent_cleanup;
        }

        BOOL connected = ConnectNamedPipe(hNamedPipe, NULL);
        DWORD connectError = connected ? ERROR_SUCCESS : GetLastError();
        if (!connected && connectError != ERROR_PIPE_CONNECTED) {
            printf("[Предупреждение] ConnectNamedPipe не установил соединение (код %lu). Повторяем попытку.\n", connectError);
            CloseHandle(hNamedPipe);
            hNamedPipe = INVALID_HANDLE_VALUE;
            StopAndCloseChild(&pi);
            if (connectError != ERROR_NO_DATA) {
                goto parent_cleanup;
            }
            Sleep(100);
            continue;
        }

        ULONG clientPid = 0;
        if (!GetNamedPipeClientProcessId(hNamedPipe, &clientPid) || clientPid != pi.dwProcessId) {
            printf("[Предупреждение] Отклонено подключение к именованному каналу: PID клиента не совпадает с PID дочернего процесса.\n");
            log_security_event("Отклонён IPC-клиент с неожиданным PID");
            DisconnectNamedPipe(hNamedPipe);
            CloseHandle(hNamedPipe);
            hNamedPipe = INVALID_HANDLE_VALUE;
            StopAndCloseChild(&pi);
            Sleep(100);
            continue;
        }

        if (MonitorStopRequested() ||
            WaitForSingleObject(hPauseEvent, INFINITE) != WAIT_OBJECT_0 ||
            MonitorStopRequested() ||
            !SnapshotCurrentPoints(pointsToSend, &wireCount) ||
            !WritePipeMessage(hNamedPipe, &protocolMagic, (DWORD)sizeof(protocolMagic)) ||
            !WritePipeMessage(hNamedPipe, &wireCount, (DWORD)sizeof(wireCount)) ||
            !WritePipeMessage(hNamedPipe, pointsToSend, (DWORD)(sizeof(Point) * wireCount))) {
            printf("[Ошибка] Ошибка ожидания события или передачи данных по IPC.\n");
            log_security_event("Ошибка передачи данных по именованному каналу");
            DisconnectNamedPipe(hNamedPipe);
            CloseHandle(hNamedPipe);
            hNamedPipe = INVALID_HANDLE_VALUE;
            StopAndCloseChild(&pi);
            if (MonitorStopRequested()) goto parent_cleanup;
            Sleep(100);
            continue;
        }

        pipe_connected = TRUE;
    }

    if (!pipe_connected || MonitorStopRequested()) goto parent_cleanup;

    // Читаем строковое сообщение только при наличии терминатора внутри принятого размера.
    char buf[100] = { 0 };
    if (!ReadPipeStringMessage(hNamedPipe, buf, (DWORD)sizeof(buf))) {
        printf("[Ошибка] Некорректное уведомление от процесса 2.\n");
        goto parent_cleanup;
    }
    if (MonitorStopRequested()) goto parent_cleanup;
    printf("[Уведомление от Процесса 2 | PID: %lu | TID: %lu]: %s\n", GetCurrentProcessId(), GetCurrentThreadId(), buf);

    // Ожидает завершения дочернего процесса или запроса на остановку от потока мониторинга.
    HANDLE childWaitHandles[2] = { hMonitorStopEvent, pi.hProcess };
    DWORD childWaitResult = WaitForMultipleObjects(2, childWaitHandles, FALSE, INFINITE);
    if (childWaitResult == WAIT_OBJECT_0) {
        printf("[МОНИТОР] Запрошено завершение приложения; останавливаем дочерний процесс.\n");
        goto parent_cleanup;
    }
    if (childWaitResult != WAIT_OBJECT_0 + 1) {
        printf("[Ошибка] Не удалось дождаться завершения процесса 2.\n");
        goto parent_cleanup;
    }

    uint32_t responseMagic = 0;
    Point returnedPoints[MAX_POINTS];
    if (!ReadPipeMessage(hNamedPipe, &responseMagic, (DWORD)sizeof(responseMagic)) ||
        responseMagic != PIPE_PROTOCOL_MAGIC ||
        !ReadPipeMessage(hNamedPipe, returnedPoints, (DWORD)(sizeof(Point) * wireCount)) ||
        !ipc_valid_points(returnedPoints, wireCount) ||
        !ipc_points_sorted_by_x(returnedPoints, wireCount)) {
        printf("[Ошибка] Ответ процесса 2 не прошёл проверку протокола или результата.\n");
        log_security_event("Отклонён некорректный результат IPC");
        goto parent_cleanup;
    }
    printf("[Процесс 1 | PID: %lu | TID: %lu] Отсортированные данные получены и проверены.\n", GetCurrentProcessId(), GetCurrentThreadId());

    exitCode = 0;

parent_cleanup:
    /* На любом пути после запуска приложения мониторинг останавливается до закрытия общих дескрипторов. */
    CleanupParentRuntime(&monitorThread, &hNamedPipe, &pi);
    return exitCode;
} 
