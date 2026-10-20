#ifndef DIRECTORY_NOTIFY_H
#define DIRECTORY_NOTIFY_H

#include <stddef.h>
#include <string.h>
#include <windows.h>

/*
 * Возвращает TRUE, если пакет уведомлений ReadDirectoryChangesW относится к data.txt.
 * Вызывающий код консервативно обрабатывает повреждённые записи и переполнение буфера:
 * при некорректных полях записи возвращается TRUE, чтобы повторно проверить файл.
 */
static inline BOOL ipc_directory_batch_touches_data_txt(const BYTE *buffer,
                                                         DWORD bytesReturned)
{
    DWORD offset = 0;
    const DWORD filenameOffset = (DWORD)offsetof(FILE_NOTIFY_INFORMATION, FileName);

    if (buffer == NULL || bytesReturned < filenameOffset) return FALSE;
    while (offset + filenameOffset <= bytesReturned) {
        const FILE_NOTIFY_INFORMATION *info =
            (const FILE_NOTIFY_INFORMATION *)(const void *)(buffer + offset);
        size_t charCount;

        if ((info->FileNameLength % sizeof(WCHAR)) != 0) return TRUE;
        charCount = info->FileNameLength / sizeof(WCHAR);
        if (charCount >= MAX_PATH) return TRUE;
        if (info->FileNameLength > bytesReturned - offset - filenameOffset) return TRUE;

        {
            WCHAR name[MAX_PATH];
            memcpy(name, info->FileName, info->FileNameLength);
            name[charCount] = L'\0';
            if (CompareStringOrdinal(name, -1, L"data.txt", -1, TRUE) == CSTR_EQUAL) {
                return TRUE;
            }
        }

        if (info->NextEntryOffset == 0) break;
        if (info->NextEntryOffset < filenameOffset + info->FileNameLength ||
            info->NextEntryOffset > bytesReturned - offset) {
            return TRUE;
        }
        offset += info->NextEntryOffset;
    }
    return FALSE;
}

#endif /* DIRECTORY_NOTIFY_H */
