#include "pkcs11.h"
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>

int main() 
{
	void *module;
	char *error;

	CK_SESSION_HANDLE session;
	unsigned char USER_PIN[] = {0x31, 0x32,0x33,0x34,0x35,0x36,0x37,0x38};
	#define USER_PIN_LEN 8

	CK_FUNCTION_LIST *functionList;
	CK_RV (*getFunctionList)(CK_FUNCTION_LIST **);

	CK_SLOT_ID_PTR slots;                             // Массив идентификаторов слотов
	CK_ULONG slotCount;                               // Количество идентификаторов слотов в массиве
	CK_MECHANISM_TYPE_PTR mechanisms;                 // Массив поддерживаемых механизмов
	CK_ULONG mechanismCount;                          // Количество поддерживаемых механизмов
	CK_OBJECT_HANDLE secretKey;                       // Хэндл симметричного ключа ГОСТ 28147-89
	CK_RV rv;                                         // Код возврата. Могут быть возвращены только ошибки, определенные в PKCS#11
	CK_ULONG i;   



	CK_OBJECT_CLASS DataObject = CKO_DATA;
	CK_UTF8CHAR label[] = "OneTwoThree";
	CK_BBOOL ckToken = CK_TRUE;
	CK_BBOOL ckPrivate = CK_FALSE;
	CK_BYTE ckValue[] = {0x01, 0x02, 0x03, 0x04};

	CK_ATTRIBUTE DataObjectTemplate[] =
	{
		{CKA_CLASS, &DataObject, sizeof(DataObject)},
		{CKA_LABEL, label, sizeof(label) - 1},
		{CKA_TOKEN, &ckToken, sizeof(ckToken)},
		{CKA_PRIVATE, &ckPrivate, sizeof(ckPrivate)},
		{CKA_VALUE, ckValue, sizeof(ckValue)}
	};

	/*************************************************************************
	* Выполнить действия для начала работы с библиотекой PKCS#11             *
	*************************************************************************/
	printf("Initialization...\n");

	/*************************************************************************
	* Загрузить библиотеку                                                   *
	*************************************************************************/
	module = dlopen("/home/user/Desktop/test_opensc/opensc-pkcs11.so", RTLD_LAZY);
	if(!module)
	{
		printf("Load failed\n");
		exit(1);
	}

	printf("Get getFunctionList function address\n");
	getFunctionList = dlsym(module, "C_GetFunctionList");
	if ((error = dlerror()) != NULL)
	{
		printf("Getting getFunctionList failed\n");
		exit(1);
	}

	printf("Get function list\n");
	rv = getFunctionList(&functionList);
	if (rv != CKR_OK)
	{
		printf("Get function list failed\n");
		exit(1);
	}

	printf("C_Initialize\n");
	rv = functionList->C_Initialize(NULL);
	if (rv != CKR_OK)
	{
		printf("C_Initialize failed\n");
		exit(1);
	}


	rv = functionList->C_GetSlotList(CK_TRUE, NULL_PTR, &slotCount);
	if (rv != CKR_OK)
	{
		printf("C_GetSlotList failed\n");
		exit(1);
	}


	slots = (CK_SLOT_ID_PTR)malloc(slotCount * sizeof(CK_SLOT_ID));
	if(slots == NULL)
	{
		printf("Malloc failed\n");
		exit(1);
	}


	rv = functionList->C_GetSlotList(CK_TRUE, slots, &slotCount);
	if (rv != CKR_OK)
	{
		printf("C_GetSlotList failed\n");
		exit(1);
	}


	/*************************************************************************
	* Открыть RW сессию в первом доступном слоте                             *
	*************************************************************************/
	rv = functionList->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session);
	if (rv != CKR_OK)
	{
		printf("C_OpenSession failed, rv = %lu \n", rv);
		exit(1);
	}

	/*************************************************************************
	* Выполнить аутентификацию Пользователя                                  *
	*************************************************************************/
	// rv = functionList->C_Login(session, CKU_USER, USER_PIN, USER_PIN_LEN);
	// if (rv != CKR_OK)
	// {
	// 	printf("C_Login failed\n");
	// 	exit(1);
	// }
	// printf("Initialization has been completed successfully.\n");


	printf("Creating data object\n");
	CK_OBJECT_HANDLE ckDataHandle;
	rv = functionList->C_CreateObject(session, DataObjectTemplate, 
									sizeof(DataObjectTemplate)/sizeof(CK_ATTRIBUTE),
									&ckDataHandle);
	if (rv != CKR_OK)
	{
		printf("C_CreateObject failed, rv = %lu \n", rv);
		exit(1);
	}
	printf("Successfully created object.\n");


	CK_BYTE ckNewValue[] = {1, 1, 1};
	CK_UTF8CHAR newLabel[] = "ThreeTwoOne";
	CK_ATTRIBUTE NewDataObjectTemplate[] =
	{
		{CKA_VALUE, ckNewValue, sizeof(ckNewValue)},
		{CKA_LABEL, newLabel, sizeof(newLabel) - 1},
	};

	printf("Modifying created object.\n");
	rv = functionList->C_SetAttributeValue(session, 
									ckDataHandle, 
									NewDataObjectTemplate,
									sizeof(NewDataObjectTemplate)/sizeof(CK_ATTRIBUTE));
	if (rv != CKR_OK)
	{
		printf("C_SetAttributeValue failed, rv = %lu \n", rv);
		exit(1);
	}
	printf("Successfully modified created object.\n");


	CK_ATTRIBUTE FindObjectTemplate[] =
	{
		{CKA_LABEL, newLabel, sizeof(newLabel) - 1},
	};
	CK_OBJECT_HANDLE phObj[16];
	CK_ULONG maxObjectCount = 16;
	CK_ULONG objCount;

	printf("Finding modified object.\n");
	rv = functionList->C_FindObjectsInit(session, 
									FindObjectTemplate, 
									1);
	if (rv != CKR_OK)
	{
		printf("C_FindObjectsInit failed, rv = %lu \n", rv);
		exit(1);
	}
	rv = functionList->C_FindObjects(session, 
									phObj, 
									maxObjectCount,
									&objCount);
	if (rv != CKR_OK)
	{
		printf("C_FindObjects failed, rv = %lu \n", rv);
		exit(1);
	}
	rv = functionList->C_FindObjectsFinal(session);
	if (rv != CKR_OK)
	{
		printf("C_FindObjectsFinal failed, rv = %lu \n", rv);
		exit(1);
	}
	printf("Successfully found modified object.\n");


	CK_BYTE ckFoundValue[] = {};
	CK_ATTRIBUTE valueAttr = {CKA_VALUE, NULL_PTR, 0};
	printf("Getting attribute of found object.\n");
	rv = functionList->C_GetAttributeValue(session,
											phObj[0],
											&valueAttr,
											1);
	if (rv != CKR_OK)
	{
		printf("C_GetAttributeValue failed, rv = %lu \n", rv);
		exit(1);
	}
	printf("Successfully got attribute of found object.\n");

	return 0;
}