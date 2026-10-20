#include <windows.h>
#include <sddl.h>
#include <assert.h>
#include <stdio.h>
#include "../ipc_security.h"

static int test_restricted_dacl(void)
{
    SECURITY_ATTRIBUTES attributes;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    PACL dacl = NULL;
    ACL_SIZE_INFORMATION aclInfo;
    PSID ownerRightsSid = NULL;
    PSID systemSid = NULL;
    BOOL foundOwnerRights = FALSE;
    BOOL foundSystem = FALSE;
    DWORD i;
    int ok = 0;

    assert(IpcCreateRestrictedSecurityAttributes(&attributes, &descriptor));
    assert(attributes.nLength == sizeof(attributes));
    assert(attributes.lpSecurityDescriptor == descriptor);
    assert(attributes.bInheritHandle == FALSE);
    assert(IsValidSecurityDescriptor(descriptor));
    assert(GetSecurityDescriptorDacl(descriptor, &daclPresent, &dacl, &daclDefaulted));
    assert(daclPresent && dacl != NULL);
    assert(GetAclInformation(dacl, &aclInfo, sizeof(aclInfo), AclSizeInformation));
    assert(aclInfo.AceCount == 2);
    assert(ConvertStringSidToSidA("S-1-3-4", &ownerRightsSid));
    assert(ConvertStringSidToSidA("S-1-5-18", &systemSid));

    for (i = 0; i < aclInfo.AceCount; ++i) {
        ACE_HEADER *header = NULL;
        assert(GetAce(dacl, i, (LPVOID *)&header));
        assert(header->AceType == ACCESS_ALLOWED_ACE_TYPE);
        ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)header;
        PSID trustee = (PSID)&ace->SidStart;
        assert(ace->Mask == GENERIC_ALL);
        if (EqualSid(trustee, ownerRightsSid)) foundOwnerRights = TRUE;
        if (EqualSid(trustee, systemSid)) foundSystem = TRUE;
    }
    assert(foundOwnerRights && foundSystem);
    ok = 1;

    if (ownerRightsSid != NULL) LocalFree(ownerRightsSid);
    if (systemSid != NULL) LocalFree(systemSid);
    IpcFreeSecurityDescriptor(&descriptor);
    return ok;
}

int main(void)
{
    assert(test_restricted_dacl());
    puts("IPC security descriptor tests: OK");
    return 0;
}
