#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>
#include "../directory_notify.h"

#define NOTIFY_HEADER_SIZE ((DWORD)offsetof(FILE_NOTIFY_INFORMATION, FileName))

static DWORD align_dword(DWORD value)
{
    return (value + sizeof(DWORD) - 1u) & ~(DWORD)(sizeof(DWORD) - 1u);
}

static DWORD write_record(BYTE *buffer, DWORD capacity, DWORD offset,
                          const WCHAR *name, DWORD action, DWORD nextOffset)
{
    FILE_NOTIFY_INFORMATION *record;
    DWORD chars = (DWORD)wcslen(name);
    DWORD nameBytes = chars * (DWORD)sizeof(WCHAR);
    DWORD required = NOTIFY_HEADER_SIZE + nameBytes;
    assert(offset + required <= capacity);
    record = (FILE_NOTIFY_INFORMATION *)(void *)(buffer + offset);
    record->NextEntryOffset = nextOffset;
    record->Action = action;
    record->FileNameLength = nameBytes;
    memcpy(record->FileName, name, nameBytes);
    return required;
}

static void test_exact_file_match(void)
{
    BYTE buffer[256] = { 0 };
    DWORD recordSize = write_record(buffer, sizeof(buffer), 0, L"data.txt",
                                    FILE_ACTION_MODIFIED, 0);
    assert(ipc_directory_batch_touches_data_txt(buffer, recordSize));
}

static void test_case_insensitive_match(void)
{
    BYTE buffer[256] = { 0 };
    DWORD recordSize = write_record(buffer, sizeof(buffer), 0, L"DATA.TXT",
                                    FILE_ACTION_ADDED, 0);
    assert(ipc_directory_batch_touches_data_txt(buffer, recordSize));
}

static void test_unrelated_filename_is_ignored(void)
{
    BYTE buffer[256] = { 0 };
    DWORD recordSize = write_record(buffer, sizeof(buffer), 0, L"security.log",
                                    FILE_ACTION_MODIFIED, 0);
    assert(!ipc_directory_batch_touches_data_txt(buffer, recordSize));
}

static void test_second_record_is_found(void)
{
    BYTE buffer[512] = { 0 };
    DWORD firstRequired = NOTIFY_HEADER_SIZE + (DWORD)(wcslen(L"other.tmp") * sizeof(WCHAR));
    DWORD secondOffset = align_dword(firstRequired);
    DWORD secondRequired;
    write_record(buffer, sizeof(buffer), 0, L"other.tmp", FILE_ACTION_MODIFIED, secondOffset);
    secondRequired = write_record(buffer, sizeof(buffer), secondOffset, L"data.txt",
                                 FILE_ACTION_RENAMED_NEW_NAME, 0);
    assert(ipc_directory_batch_touches_data_txt(buffer, secondOffset + secondRequired));
}

static void test_truncated_notification_is_safe(void)
{
    BYTE buffer[8] = { 0 };
    assert(!ipc_directory_batch_touches_data_txt(NULL, sizeof(buffer)));
    assert(!ipc_directory_batch_touches_data_txt(buffer, 0));
    assert(!ipc_directory_batch_touches_data_txt(buffer, NOTIFY_HEADER_SIZE - 1));
}

int main(void)
{
    test_exact_file_match();
    test_case_insensitive_match();
    test_unrelated_filename_is_ignored();
    test_second_record_is_found();
    test_truncated_notification_is_safe();
    puts("Directory notification tests: OK");
    return 0;
}
