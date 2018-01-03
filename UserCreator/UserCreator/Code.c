#include <Windows.h>
#include <tchar.h>
#include <wchar.h>
#include <LM.h>
#include <sddl.h>

#pragma comment(lib, "Netapi32.lib")
#define MAX_NAME 256

VOID ShowError(DWORD errorCode)
{
	//FormatMessageW
	DWORD flags =	FORMAT_MESSAGE_ALLOCATE_BUFFER |
					FORMAT_MESSAGE_FROM_SYSTEM |
					FORMAT_MESSAGE_IGNORE_INSERTS;
	LPWSTR errorMessage;
	DWORD size = 0;

	if (!FormatMessageW(flags, NULL, errorCode, 0, (LPWSTR)&errorMessage, size, NULL))
	{
		fwprintf(stderr, L"Could not get the format message, error code: %u\n", GetLastError());
		exit(1);
	}

	wprintf(L"\n%s\n", errorMessage);

	LocalFree(errorMessage);
}


int wmain(int argc, WCHAR **argv)
{
	//NetUserAdd function
	NET_API_STATUS addUser;
	DWORD infoLevel = 1;		//USER_INFO_1
	USER_INFO_1 userData;
	DWORD paramError=0;

	//LocalAlloc
	UINT memAttributes = LMEM_FIXED;
	SIZE_T sidSize = SECURITY_MAX_SID_SIZE;

	//CreateWellKnownSid
	WELL_KNOWN_SID_TYPE sidType = WinBuiltinUsersSid;
	PSID groupSID;

	//LookupAccountSid
	WCHAR name[MAX_NAME];
	DWORD nameSize = MAX_NAME;
	WCHAR domainName[MAX_NAME];
	DWORD domainNameSize = MAX_NAME;
	SID_NAME_USE accountType;

	//LookupAccountName
	PSID accountSID;
	SID_NAME_USE typeOfAccount;

	//NetLocalGroupAddMembers
	NET_API_STATUS localGroupAdd;
	DWORD levelOfData = 0;	//LOCALGROUP_MEMBERS_INFO_0
	LOCALGROUP_MEMBERS_INFO_0 localMembers;
	DWORD totalEntries = 0;
	

	if (argc != 3)	//Got just one argument.
	{
		fwprintf(stderr, L"\nUsage: %s [UserName] [Privilege]\n", *argv);
		fwprintf(stderr, L"\n[Privilege]: --user | --admin\n");
		return 1;		

	}

	/*if ((_wcsicmp(argv[2], L"--user") == 0))
	{

	}		
	else if ((_wcsicmp(argv[2], L"--admin") == 0))
	{

	}		
	else
	{
		fwprintf(stderr, L"\nUsage: %s [UserName] [Privilege]\n", *argv);
		fwprintf(stderr, L"\n[Privilege]: --user | --admin\n");
		return 1;
	}*/

	//Set up USER_INFO_1 structure
	userData.usri1_name = argv[1];
	userData.usri1_password = NULL;
	userData.usri1_priv = USER_PRIV_USER;
	userData.usri1_home_dir = NULL;
	userData.usri1_comment = NULL;
	userData.usri1_flags = UF_SCRIPT;
	userData.usri1_script_path = NULL;

	addUser = NetUserAdd(NULL, infoLevel, (LPBYTE)&userData, &paramError);

	if (addUser != NERR_Success)
	{
		fwprintf(stderr, L"\nA system error has ocurred: %d\n", addUser);
		
		return 1;
	}
	else
	{

		//Let's allocate memory for the SID
		if (!(groupSID = LocalAlloc(memAttributes, sidSize)))	//if fails
		{
			wprintf(L"\nMemory allocation failed: \n");
			ShowError(GetLastError());
			exit(1);

		}

		//Allocate memory for LookupAccountName
		if (!(accountSID = LocalAlloc(memAttributes, sidSize)))
		{
			wprintf(L"\nMemory allocation for account SID failed: \n");
			ShowError(GetLastError());
			exit(1);

		}

		//Let's create a SID for Users group
		if (!CreateWellKnownSid(sidType, NULL, groupSID, (DWORD*)&sidSize))
		{
			fwprintf(stderr, L"\nError getting the SID: \n");
			ShowError(GetLastError());
			exit(1);
		}
		else
		{
			
			if (!LookupAccountSidW(NULL, groupSID, name, &nameSize,
				domainName, &domainNameSize, &accountType))
			{
				fwprintf(stderr, L"Error getting name from SID: \n");
				ShowError(GetLastError());
				return 1;

			}

			if (!LookupAccountNameW(NULL, argv[1], accountSID,
									(LPDWORD)&sidSize, NULL, 0, &typeOfAccount))
			{
				fwprintf(stderr, L"Error getting SID from name: \n");
				ShowError(GetLastError());
				return 1;

			}

			//Here I should be able to use NetLocalGroupAddMembers
			//to add the user passed as argument to the Users group. 
			localMembers.lgrmi0_sid = accountSID;

			localGroupAdd = NetLocalGroupAddMembers(NULL, name, levelOfData, (LPBYTE)&localMembers, totalEntries);

			if (localGroupAdd != NERR_Success)
			{
				fwprintf(stderr, L"Error adding member to the local group: \n");
				ShowError(GetLastError());
				return 1;
			}
			else
			{
				wprintf(L"\nUser %s has been successfully added.\n", argv[1]);

			}


		}

		LocalFree(groupSID);
		LocalFree(accountSID);
		
	}

	return 0;
}