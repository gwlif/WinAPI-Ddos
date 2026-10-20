#ifndef IPC_SECURITY_H
#define IPC_SECURITY_H

#include <windows.h>
#include <sddl.h>

/*
 * Ограниченная DACL для IPC-объектов текущего запуска:
 *   OW = права владельца (созданный объект принадлежит текущему пользователю)
 *   SY = LocalSystem
 * Разрешения не выдаются группам Everyone, Authenticated Users и анонимным пользователям.
 * Вызывающий код должен освободить возвращённый самодостаточный дескриптор через LocalFree.
 */
static BOOL IpcCreateRestrictedSecurityAttributes(
    SECURITY_ATTRIBUTES *attributes,
    PSECURITY_DESCRIPTOR *descriptor)
{
    if (attributes == NULL || descriptor == NULL) return FALSE;
    *descriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:P(A;;GA;;;OW)(A;;GA;;;SY)", SDDL_REVISION_1,
            descriptor, NULL)) {
        return FALSE;
    }
    attributes->nLength = sizeof(*attributes);
    attributes->lpSecurityDescriptor = *descriptor;
    attributes->bInheritHandle = FALSE;
    return TRUE;
}

static void IpcFreeSecurityDescriptor(PSECURITY_DESCRIPTOR *descriptor)
{
    if (descriptor != NULL && *descriptor != NULL) {
        LocalFree(*descriptor);
        *descriptor = NULL;
    }
}

#endif /* IPC_SECURITY_H */
