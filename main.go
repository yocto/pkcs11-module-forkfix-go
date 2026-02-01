package main

// #cgo LDFLAGS: -ldl
// #define _GNU_SOURCE
// #include <dlfcn.h>
// #include "cgo.h"
import "C"
import "fmt"
import "os"
import "unsafe"

import "github.com/ebitengine/purego"

var cryptokiVersion = C.CK_VERSION{
	major: 3,
	minor: 1,
}

var interfaces = []C.CK_INTERFACE{
	C.CK_INTERFACE{
		pInterfaceName: (*C.CK_CHAR)(unsafe.SliceData([]byte("PKCS 11"))),
		pFunctionList:  (C.CK_VOID_PTR)(&functionList30),
		flags:          0x0,
	},
}

var functionList = C.CK_FUNCTION_LIST{
	version: cryptokiVersion,
	// Version 2.0 and later
	C_Initialize:          (C.CK_C_Initialize)(C.C_Initialize),
	C_Finalize:            (C.CK_C_Finalize)(C.C_Finalize),
	C_GetInfo:             (C.CK_C_GetInfo)(C.C_GetInfo),
	C_GetFunctionList:     (C.CK_C_GetFunctionList)(C.C_GetFunctionList),
	C_GetSlotList:         (C.CK_C_GetSlotList)(C.C_GetSlotList),
	C_GetSlotInfo:         (C.CK_C_GetSlotInfo)(C.C_GetSlotInfo),
	C_GetTokenInfo:        (C.CK_C_GetTokenInfo)(C.C_GetTokenInfo),
	C_GetMechanismList:    (C.CK_C_GetMechanismList)(C.C_GetMechanismList),
	C_GetMechanismInfo:    (C.CK_C_GetMechanismInfo)(C.C_GetMechanismInfo),
	C_InitToken:           (C.CK_C_InitToken)(C.C_InitToken),
	C_InitPIN:             (C.CK_C_InitPIN)(C.C_InitPIN),
	C_SetPIN:              (C.CK_C_SetPIN)(C.C_SetPIN),
	C_OpenSession:         (C.CK_C_OpenSession)(C.C_OpenSession),
	C_CloseSession:        (C.CK_C_CloseSession)(C.C_CloseSession),
	C_CloseAllSessions:    (C.CK_C_CloseAllSessions)(C.C_CloseAllSessions),
	C_GetSessionInfo:      (C.CK_C_GetSessionInfo)(C.C_GetSessionInfo),
	C_GetOperationState:   (C.CK_C_GetOperationState)(C.C_GetOperationState),
	C_SetOperationState:   (C.CK_C_SetOperationState)(C.C_SetOperationState),
	C_Login:               (C.CK_C_Login)(C.C_Login),
	C_Logout:              (C.CK_C_Logout)(C.C_Logout),
	C_CreateObject:        (C.CK_C_CreateObject)(C.C_CreateObject),
	C_CopyObject:          (C.CK_C_CopyObject)(C.C_CopyObject),
	C_DestroyObject:       (C.CK_C_DestroyObject)(C.C_DestroyObject),
	C_GetObjectSize:       (C.CK_C_GetObjectSize)(C.C_GetObjectSize),
	C_GetAttributeValue:   (C.CK_C_GetAttributeValue)(C.C_GetAttributeValue),
	C_SetAttributeValue:   (C.CK_C_SetAttributeValue)(C.C_SetAttributeValue),
	C_FindObjectsInit:     (C.CK_C_FindObjectsInit)(C.C_FindObjectsInit),
	C_FindObjects:         (C.CK_C_FindObjects)(C.C_FindObjects),
	C_FindObjectsFinal:    (C.CK_C_FindObjectsFinal)(C.C_FindObjectsFinal),
	C_EncryptInit:         (C.CK_C_EncryptInit)(C.C_EncryptInit),
	C_Encrypt:             (C.CK_C_Encrypt)(C.C_Encrypt),
	C_EncryptUpdate:       (C.CK_C_EncryptUpdate)(C.C_EncryptUpdate),
	C_EncryptFinal:        (C.CK_C_EncryptFinal)(C.C_EncryptFinal),
	C_DecryptInit:         (C.CK_C_DecryptInit)(C.C_DecryptInit),
	C_Decrypt:             (C.CK_C_Decrypt)(C.C_Decrypt),
	C_DecryptUpdate:       (C.CK_C_DecryptUpdate)(C.C_DecryptUpdate),
	C_DecryptFinal:        (C.CK_C_DecryptFinal)(C.C_DecryptUpdate),
	C_DigestInit:          (C.CK_C_DigestInit)(C.C_DigestInit),
	C_Digest:              (C.CK_C_Digest)(C.C_Digest),
	C_DigestUpdate:        (C.CK_C_DigestUpdate)(C.C_DigestUpdate),
	C_DigestKey:           (C.CK_C_DigestKey)(C.C_DigestKey),
	C_DigestFinal:         (C.CK_C_DigestFinal)(C.C_DigestFinal),
	C_SignInit:            (C.CK_C_SignInit)(C.C_SignInit),
	C_Sign:                (C.CK_C_Sign)(C.C_Sign),
	C_SignUpdate:          (C.CK_C_SignUpdate)(C.C_SignUpdate),
	C_SignFinal:           (C.CK_C_SignFinal)(C.C_SignFinal),
	C_SignRecoverInit:     (C.CK_C_SignRecoverInit)(C.C_SignRecoverInit),
	C_SignRecover:         (C.CK_C_SignRecover)(C.C_SignRecover),
	C_VerifyInit:          (C.CK_C_VerifyInit)(C.C_VerifyInit),
	C_Verify:              (C.CK_C_Verify)(C.C_Verify),
	C_VerifyUpdate:        (C.CK_C_VerifyUpdate)(C.C_VerifyUpdate),
	C_VerifyFinal:         (C.CK_C_VerifyFinal)(C.C_VerifyFinal),
	C_VerifyRecoverInit:   (C.CK_C_VerifyRecoverInit)(C.C_VerifyRecoverInit),
	C_VerifyRecover:       (C.CK_C_VerifyRecover)(C.C_VerifyRecover),
	C_DigestEncryptUpdate: (C.CK_C_DigestEncryptUpdate)(C.C_DigestEncryptUpdate),
	C_DecryptDigestUpdate: (C.CK_C_DecryptDigestUpdate)(C.C_DecryptDigestUpdate),
	C_SignEncryptUpdate:   (C.CK_C_SignEncryptUpdate)(C.C_SignEncryptUpdate),
	C_DecryptVerifyUpdate: (C.CK_C_DecryptVerifyUpdate)(C.C_DecryptVerifyUpdate),
	C_GenerateKey:         (C.CK_C_GenerateKey)(C.C_GenerateKey),
	C_GenerateKeyPair:     (C.CK_C_GenerateKeyPair)(C.C_GenerateKeyPair),
	C_WrapKey:             (C.CK_C_WrapKey)(C.C_WrapKey),
	C_UnwrapKey:           (C.CK_C_UnwrapKey)(C.C_UnwrapKey),
	C_DeriveKey:           (C.CK_C_DeriveKey)(C.C_DeriveKey),
	C_SeedRandom:          (C.CK_C_SeedRandom)(C.C_SeedRandom),
	C_GenerateRandom:      (C.CK_C_GenerateRandom)(C.C_GenerateRandom),
	C_GetFunctionStatus:   (C.CK_C_GetFunctionStatus)(C.C_GetFunctionStatus),
	C_CancelFunction:      (C.CK_C_CancelFunction)(C.C_CancelFunction),
	// Version 2.1 and later
	C_WaitForSlotEvent: (C.CK_C_WaitForSlotEvent)(C.C_WaitForSlotEvent),
}

var functionList30 = C.CK_FUNCTION_LIST_3_0{
	version: cryptokiVersion,
	// Version 2.0 and later
	C_Initialize:          (C.CK_C_Initialize)(C.C_Initialize),
	C_Finalize:            (C.CK_C_Finalize)(C.C_Finalize),
	C_GetInfo:             (C.CK_C_GetInfo)(C.C_GetInfo),
	C_GetFunctionList:     (C.CK_C_GetFunctionList)(C.C_GetFunctionList),
	C_GetSlotList:         (C.CK_C_GetSlotList)(C.C_GetSlotList),
	C_GetSlotInfo:         (C.CK_C_GetSlotInfo)(C.C_GetSlotInfo),
	C_GetTokenInfo:        (C.CK_C_GetTokenInfo)(C.C_GetTokenInfo),
	C_GetMechanismList:    (C.CK_C_GetMechanismList)(C.C_GetMechanismList),
	C_GetMechanismInfo:    (C.CK_C_GetMechanismInfo)(C.C_GetMechanismInfo),
	C_InitToken:           (C.CK_C_InitToken)(C.C_InitToken),
	C_InitPIN:             (C.CK_C_InitPIN)(C.C_InitPIN),
	C_SetPIN:              (C.CK_C_SetPIN)(C.C_SetPIN),
	C_OpenSession:         (C.CK_C_OpenSession)(C.C_OpenSession),
	C_CloseSession:        (C.CK_C_CloseSession)(C.C_CloseSession),
	C_CloseAllSessions:    (C.CK_C_CloseAllSessions)(C.C_CloseAllSessions),
	C_GetSessionInfo:      (C.CK_C_GetSessionInfo)(C.C_GetSessionInfo),
	C_GetOperationState:   (C.CK_C_GetOperationState)(C.C_GetOperationState),
	C_SetOperationState:   (C.CK_C_SetOperationState)(C.C_SetOperationState),
	C_Login:               (C.CK_C_Login)(C.C_Login),
	C_Logout:              (C.CK_C_Logout)(C.C_Logout),
	C_CreateObject:        (C.CK_C_CreateObject)(C.C_CreateObject),
	C_CopyObject:          (C.CK_C_CopyObject)(C.C_CopyObject),
	C_DestroyObject:       (C.CK_C_DestroyObject)(C.C_DestroyObject),
	C_GetObjectSize:       (C.CK_C_GetObjectSize)(C.C_GetObjectSize),
	C_GetAttributeValue:   (C.CK_C_GetAttributeValue)(C.C_GetAttributeValue),
	C_SetAttributeValue:   (C.CK_C_SetAttributeValue)(C.C_SetAttributeValue),
	C_FindObjectsInit:     (C.CK_C_FindObjectsInit)(C.C_FindObjectsInit),
	C_FindObjects:         (C.CK_C_FindObjects)(C.C_FindObjects),
	C_FindObjectsFinal:    (C.CK_C_FindObjectsFinal)(C.C_FindObjectsFinal),
	C_EncryptInit:         (C.CK_C_EncryptInit)(C.C_EncryptInit),
	C_Encrypt:             (C.CK_C_Encrypt)(C.C_Encrypt),
	C_EncryptUpdate:       (C.CK_C_EncryptUpdate)(C.C_EncryptUpdate),
	C_EncryptFinal:        (C.CK_C_EncryptFinal)(C.C_EncryptFinal),
	C_DecryptInit:         (C.CK_C_DecryptInit)(C.C_DecryptInit),
	C_Decrypt:             (C.CK_C_Decrypt)(C.C_Decrypt),
	C_DecryptUpdate:       (C.CK_C_DecryptUpdate)(C.C_DecryptUpdate),
	C_DecryptFinal:        (C.CK_C_DecryptFinal)(C.C_DecryptUpdate),
	C_DigestInit:          (C.CK_C_DigestInit)(C.C_DigestInit),
	C_Digest:              (C.CK_C_Digest)(C.C_Digest),
	C_DigestUpdate:        (C.CK_C_DigestUpdate)(C.C_DigestUpdate),
	C_DigestKey:           (C.CK_C_DigestKey)(C.C_DigestKey),
	C_DigestFinal:         (C.CK_C_DigestFinal)(C.C_DigestFinal),
	C_SignInit:            (C.CK_C_SignInit)(C.C_SignInit),
	C_Sign:                (C.CK_C_Sign)(C.C_Sign),
	C_SignUpdate:          (C.CK_C_SignUpdate)(C.C_SignUpdate),
	C_SignFinal:           (C.CK_C_SignFinal)(C.C_SignFinal),
	C_SignRecoverInit:     (C.CK_C_SignRecoverInit)(C.C_SignRecoverInit),
	C_SignRecover:         (C.CK_C_SignRecover)(C.C_SignRecover),
	C_VerifyInit:          (C.CK_C_VerifyInit)(C.C_VerifyInit),
	C_Verify:              (C.CK_C_Verify)(C.C_Verify),
	C_VerifyUpdate:        (C.CK_C_VerifyUpdate)(C.C_VerifyUpdate),
	C_VerifyFinal:         (C.CK_C_VerifyFinal)(C.C_VerifyFinal),
	C_VerifyRecoverInit:   (C.CK_C_VerifyRecoverInit)(C.C_VerifyRecoverInit),
	C_VerifyRecover:       (C.CK_C_VerifyRecover)(C.C_VerifyRecover),
	C_DigestEncryptUpdate: (C.CK_C_DigestEncryptUpdate)(C.C_DigestEncryptUpdate),
	C_DecryptDigestUpdate: (C.CK_C_DecryptDigestUpdate)(C.C_DecryptDigestUpdate),
	C_SignEncryptUpdate:   (C.CK_C_SignEncryptUpdate)(C.C_SignEncryptUpdate),
	C_DecryptVerifyUpdate: (C.CK_C_DecryptVerifyUpdate)(C.C_DecryptVerifyUpdate),
	C_GenerateKey:         (C.CK_C_GenerateKey)(C.C_GenerateKey),
	C_GenerateKeyPair:     (C.CK_C_GenerateKeyPair)(C.C_GenerateKeyPair),
	C_WrapKey:             (C.CK_C_WrapKey)(C.C_WrapKey),
	C_UnwrapKey:           (C.CK_C_UnwrapKey)(C.C_UnwrapKey),
	C_DeriveKey:           (C.CK_C_DeriveKey)(C.C_DeriveKey),
	C_SeedRandom:          (C.CK_C_SeedRandom)(C.C_SeedRandom),
	C_GenerateRandom:      (C.CK_C_GenerateRandom)(C.C_GenerateRandom),
	C_GetFunctionStatus:   (C.CK_C_GetFunctionStatus)(C.C_GetFunctionStatus),
	C_CancelFunction:      (C.CK_C_CancelFunction)(C.C_CancelFunction),
	// Version 2.1 and later
	C_WaitForSlotEvent: (C.CK_C_WaitForSlotEvent)(C.C_WaitForSlotEvent),
	// Version 3.0 and later
	C_GetInterfaceList:    (C.CK_C_GetInterfaceList)(C.C_GetInterfaceList),
	C_GetInterface:        (C.CK_C_GetInterface)(C.C_GetInterface),
	C_LoginUser:           (C.CK_C_LoginUser)(C.C_LoginUser),
	C_SessionCancel:       (C.CK_C_SessionCancel)(C.C_SessionCancel),
	C_MessageEncryptInit:  (C.CK_C_MessageEncryptInit)(C.C_MessageEncryptInit),
	C_EncryptMessage:      (C.CK_C_EncryptMessage)(C.C_EncryptMessage),
	C_EncryptMessageBegin: (C.CK_C_EncryptMessageBegin)(C.C_EncryptMessageBegin),
	C_EncryptMessageNext:  (C.CK_C_EncryptMessageNext)(C.C_EncryptMessageNext),
	C_MessageEncryptFinal: (C.CK_C_MessageEncryptFinal)(C.C_MessageEncryptFinal),
	C_MessageDecryptInit:  (C.CK_C_MessageDecryptInit)(C.C_MessageDecryptInit),
	C_DecryptMessage:      (C.CK_C_DecryptMessage)(C.C_DecryptMessage),
	C_DecryptMessageBegin: (C.CK_C_DecryptMessageBegin)(C.C_DecryptMessageBegin),
	C_DecryptMessageNext:  (C.CK_C_DecryptMessageNext)(C.C_DecryptMessageBegin),
	C_MessageDecryptFinal: (C.CK_C_MessageDecryptFinal)(C.C_MessageDecryptFinal),
	C_MessageSignInit:     (C.CK_C_MessageSignInit)(C.C_MessageSignInit),
	C_SignMessage:         (C.CK_C_SignMessage)(C.C_SignMessage),
	C_SignMessageBegin:    (C.CK_C_SignMessageBegin)(C.C_SignMessageBegin),
	C_SignMessageNext:     (C.CK_C_SignMessageNext)(C.C_SignMessageNext),
	C_MessageSignFinal:    (C.CK_C_MessageSignFinal)(C.C_MessageSignFinal),
	C_MessageVerifyInit:   (C.CK_C_MessageVerifyInit)(C.C_MessageVerifyInit),
	C_VerifyMessage:       (C.CK_C_VerifyMessage)(C.C_VerifyMessage),
	C_VerifyMessageBegin:  (C.CK_C_VerifyMessageBegin)(C.C_VerifyMessageBegin),
	C_VerifyMessageNext:   (C.CK_C_VerifyMessageNext)(C.C_VerifyMessageNext),
	C_MessageVerifyFinal:  (C.CK_C_MessageVerifyFinal)(C.C_MessageVerifyFinal),
}

func main() {}

var libraryHandle unsafe.Pointer = nil
var libraryPID int = -1

func getDynamicLibrary() unsafe.Pointer {
	if libraryHandle == nil || libraryPID == -1 || libraryPID != os.Getpid() {
		if libraryHandle != nil {
			C.dlclose(libraryHandle)
		}
		libraryHandle = C.dlmopen(C.LM_ID_NEWLM, C.CString(os.Getenv("PKCS11_SUBMODULE")), C.RTLD_LAZY)
		if libraryHandle == nil {
			return nil
		}
		libraryPID = os.Getpid()
	}
	return libraryHandle
}

func getDynamicLibrarySymbol(functionName string) uintptr {
	lh := getDynamicLibrary()
	if lh == nil {
		return 0
	}
	return uintptr(C.dlsym(lh, C.CString(functionName)))
}

//export C_CancelFunction
func C_CancelFunction(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_CancelFunction")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession)
}

//export C_CloseAllSessions
func C_CloseAllSessions(slotID C.CK_SLOT_ID) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_CloseAllSessions")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SLOT_ID) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(slotID)
}

//export C_CloseSession
func C_CloseSession(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_CloseSession")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession)
}

//export C_CopyObject
func C_CopyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/, phNewObject C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_CopyObject")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE, C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, hObject, pTemplate, ulCount, phNewObject)
}

//export C_CreateObject
func C_CreateObject(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/, phObject C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_CreateObject")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pTemplate, ulCount, phObject)
}

//export C_Decrypt
func C_Decrypt(hSession C.CK_SESSION_HANDLE, pEncryptedData C.CK_BYTE_PTR, ulEncryptedDataLen C.CK_ULONG /*usEncryptedDataLen C.CK_USHORT (v1.0)*/, pData C.CK_BYTE_PTR, pulDataLen C.CK_ULONG_PTR /*pusDataLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_Decrypt")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen)
}

//export C_DecryptDigestUpdate
func C_DecryptDigestUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	symbol := getDynamicLibrarySymbol("C_DecryptDigestUpdate")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen)
}

//export C_DecryptFinal
func C_DecryptFinal(hSession C.CK_SESSION_HANDLE, pLastPart C.CK_BYTE_PTR, pulLastPartLen C.CK_ULONG_PTR /*usLastPartLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_DecryptFinal")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pLastPart, pulLastPartLen)
}

//export C_DecryptInit
func C_DecryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_DecryptInit")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pMechanism, hKey)
}

//export C_DecryptMessage
func C_DecryptMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG, pCiphertext C.CK_BYTE_PTR, ulCiphertextLen C.CK_ULONG, pPlaintext C.CK_BYTE_PTR, pulPlaintextLen C.CK_ULONG_PTR) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_DecryptMessage")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen, pCiphertext, ulCiphertextLen, pPlaintext, pulPlaintextLen)
}

//export C_DecryptMessageBegin
func C_DecryptMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_DecryptMessageBegin")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen)
}

//export C_DecryptMessageNext
func C_DecryptMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pCiphertextPart C.CK_BYTE_PTR, ulCiphertextPartLen C.CK_ULONG, pPlaintextPart C.CK_BYTE_PTR, pulPlaintextPartLen C.CK_ULONG_PTR, flags C.CK_FLAGS) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_DecryptMessageNext")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR, C.CK_FLAGS) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pParameter, ulParameterLen, pCiphertextPart, ulCiphertextPartLen, pPlaintextPart, pulPlaintextPartLen, flags)
}

//export C_DecryptUpdate
func C_DecryptUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG /*usEncryptedPartLen C.CK_USHORT (v1.0)*/, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR /*pusPartLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_DecryptUpdate")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen)
}

//export C_DecryptVerifyUpdate
func C_DecryptVerifyUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	symbol := getDynamicLibrarySymbol("C_DecryptVerifyUpdate")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen)
}

//export C_DeriveKey
func C_DeriveKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hBaseKey C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulAttributeCount C.CK_ULONG /*usAttributeCount C.CK_USHORT (v1.0)*/, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_DeriveKey")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE, C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey)
}

//export C_DestroyObject
func C_DestroyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_DestroyObject")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, hObject)
}

//export C_Digest
func C_Digest(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pDigest C.CK_BYTE_PTR, pulDigestLen C.CK_ULONG_PTR /*pusDigestLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_Digest")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pData, ulDataLen, pDigest, pulDigestLen)
}

//export C_DigestEncryptUpdate
func C_DigestEncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	symbol := getDynamicLibrarySymbol("C_DigestEncryptUpdate")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen)
}

//export C_DigestFinal
func C_DigestFinal(hSession C.CK_SESSION_HANDLE, pDigest C.CK_BYTE_PTR, pulDigestLen C.CK_ULONG_PTR /*pusDigestLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_DigestFinal")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pDigest, pulDigestLen)
}

//export C_DigestInit
func C_DigestInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_DigestInit")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pMechanism)
}

//export C_DigestKey
func C_DigestKey(hSession C.CK_SESSION_HANDLE, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v2.0
	symbol := getDynamicLibrarySymbol("C_DigestKey")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, hKey)
}

//export C_DigestUpdate
func C_DigestUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG /*usPartLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_DigestUpdate")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pPart, ulPartLen)
}

//export C_Encrypt
func C_Encrypt(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pEncryptedData C.CK_BYTE_PTR, pulEncryptedDataLen C.CK_ULONG_PTR /*pusEncryptedDataLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_Encrypt")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen)
}

//export C_EncryptFinal
func C_EncryptFinal(hSession C.CK_SESSION_HANDLE, pLastEncryptedPart C.CK_BYTE_PTR, pulLastEncryptedPartLen C.CK_ULONG_PTR /*pusEncryptedPartLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_EncryptFinal")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pLastEncryptedPart, pulLastEncryptedPartLen)
}

//export C_EncryptInit
func C_EncryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_EncryptInit")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pMechanism, hKey)
}

//export C_EncryptMessage
func C_EncryptMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG, pPlaintext C.CK_BYTE_PTR, ulPlaintextLen C.CK_ULONG, pCiphertext C.CK_BYTE_PTR, pulCiphertextLen C.CK_ULONG_PTR) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_EncryptMessage")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen, pPlaintext, ulPlaintextLen, pCiphertext, pulCiphertextLen)
}

//export C_EncryptMessageBegin
func C_EncryptMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_EncryptMessageBegin")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen)
}

//export C_EncryptMessageNext
func C_EncryptMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pPlaintextPart C.CK_BYTE_PTR, ulPlaintextPartLen C.CK_ULONG, pCiphertextPart C.CK_BYTE_PTR, pulCiphertextPartLen C.CK_ULONG_PTR, flags C.CK_FLAGS) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_EncryptMessageNext")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR, C.CK_FLAGS) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pParameter, ulParameterLen, pPlaintextPart, ulPlaintextPartLen, pCiphertextPart, pulCiphertextPartLen, flags)
}

//export C_EncryptUpdate
func C_EncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG /*usPartLen C.CK_USHORT (v1.0)*/, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR /*pusEncryptedPartLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_EncryptUpdate")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen)
}

//export C_Finalize
func C_Finalize(pReserved C.CK_VOID_PTR) C.CK_RV { // Since v2.0
	symbol := getDynamicLibrarySymbol("C_Finalize")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_VOID_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(pReserved)
}

//export C_FindObjects
func C_FindObjects(hSession C.CK_SESSION_HANDLE, phObject C.CK_OBJECT_HANDLE_PTR, ulMaxObjectCount C.CK_ULONG /*usMaxObjectCount C.CK_USHORT (v1.0)*/, pulObjectCount C.CK_ULONG_PTR /*pusObjectCount C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_FindObjects")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE_PTR, C.CK_ULONG, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, phObject, ulMaxObjectCount, pulObjectCount)
}

//export C_FindObjectsFinal
func C_FindObjectsFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v2.0
	symbol := getDynamicLibrarySymbol("C_FindObjectsFinal")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession)
}

//export C_FindObjectsInit
func C_FindObjectsInit(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_FindObjectsInit")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_ATTRIBUTE_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pTemplate, ulCount)
}

//export C_GenerateKey
func C_GenerateKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_GenerateKey")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pMechanism, pTemplate, ulCount, phKey)
}

//export C_GenerateKeyPair
func C_GenerateKeyPair(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pPublicKeyTemplate C.CK_ATTRIBUTE_PTR, ulPublicKeyAttributeCount C.CK_ULONG /*usPublicKeyAttributeCount C.CK_USHORT (v1.0)*/, pPrivateKeyTemplate C.CK_ATTRIBUTE_PTR, ulPrivateKeyAttributeCount C.CK_ULONG /*usPrivateKeyAttributeCount C.CK_USHORT (v1.0)*/, phPrivateKey C.CK_OBJECT_HANDLE_PTR, phPublicKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_GenerateKeyPair")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR, C.CK_OBJECT_HANDLE_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPrivateKey, phPublicKey)
}

//export C_GenerateRandom
func C_GenerateRandom(hSession C.CK_SESSION_HANDLE, pRandomData C.CK_BYTE_PTR, ulRandomLen C.CK_ULONG /*usRandomLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_GenerateRandom")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pRandomData, ulRandomLen)
}

//export C_GetAttributeValue
func C_GetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_GetAttributeValue")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE, C.CK_ATTRIBUTE_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, hObject, pTemplate, ulCount)
}

//export C_GetFunctionList
func C_GetFunctionList(ppFunctionList C.CK_FUNCTION_LIST_PTR_PTR) C.CK_RV { // Since v2.0
	if ppFunctionList == nil {
		fmt.Println("Function list pointer cannot be null.")
		return C.CKR_ARGUMENTS_BAD
	}

	*ppFunctionList = &functionList

	return C.CKR_OK
}

//export C_GetFunctionStatus
func C_GetFunctionStatus(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_GetFunctionStatus")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession)
}

//export C_GetInfo
func C_GetInfo(pInfo C.CK_INFO_PTR) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_GetInfo")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_INFO_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(pInfo)
}

//export C_GetInterface
func C_GetInterface(pInterfaceName C.CK_UTF8CHAR_PTR, pVersion C.CK_VERSION_PTR, ppInterface C.CK_INTERFACE_PTR_PTR, flags C.CK_FLAGS) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_GetInterface(pInterfaceName=%+v, pVersion=%+v, ppInterface=%+v, flags=%+v)\n", pInterfaceName, pVersion, ppInterface, flags)

	var matchingInterface C.CK_INTERFACE_PTR

	for _, interfaceItem := range interfaces {
		var interfaceNameMatches bool = false
		var versionMatches bool = false
		var flagMatches bool = false

		if pInterfaceName == nil {
			interfaceNameMatches = true
		} else {
			interfaceName := (C.CK_UTF8CHAR_PTR)(interfaceItem.pInterfaceName)
			interfaceNameMatches = *pInterfaceName == *interfaceName
		}
		if pVersion == nil {
			versionMatches = true
		} else {
			version := (C.CK_VERSION_PTR)(interfaceItem.pFunctionList)
			versionMatches = (*pVersion).major == version.major && (*pVersion).minor == version.minor
		}
		if flags == 0x0 {
			flagMatches = true
		} else {
			flagMatches = flags == interfaceItem.flags
		}

		if interfaceNameMatches && versionMatches && flagMatches {
			matchingInterface = &interfaceItem
			break
		}
	}

	if matchingInterface != nil {
		*ppInterface = matchingInterface
		return C.CKR_OK
	}
	return C.CKR_ARGUMENTS_BAD
}

//export C_GetInterfaceList
func C_GetInterfaceList(pInterfaceList C.CK_INTERFACE_PTR, pulCount C.CK_ULONG_PTR) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_GetInterfaceList(pInterfaceList=%+v, pulCount=%+v)\n", pInterfaceList, pulCount)

	if pulCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var INTERFACE_COUNT = len(interfaces)

	if pInterfaceList == nil {
		*pulCount = (C.CK_ULONG)(INTERFACE_COUNT)
		return C.CKR_OK
	}

	const CK_INTERFACE_SIZE = C.sizeof_CK_INTERFACE

	*pulCount = (C.CK_ULONG)(INTERFACE_COUNT)
	if int(unsafe.Sizeof(*pInterfaceList)) < INTERFACE_COUNT*int(CK_INTERFACE_SIZE) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	pointerAsSliceDestination := unsafe.Slice(pInterfaceList, INTERFACE_COUNT)
	copy(pointerAsSliceDestination, interfaces)

	return C.CKR_OK
}

//export C_GetMechanismInfo
func C_GetMechanismInfo(slotID C.CK_SLOT_ID, _type C.CK_MECHANISM_TYPE, pInfo C.CK_MECHANISM_INFO_PTR) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_GetMechanismInfo")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SLOT_ID, C.CK_MECHANISM_TYPE, C.CK_MECHANISM_INFO_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(slotID, _type, pInfo)
}

//export C_GetMechanismList
func C_GetMechanismList(slotID C.CK_SLOT_ID, pMechanismList C.CK_MECHANISM_TYPE_PTR, pulCount C.CK_ULONG_PTR /*pusCount C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_GetMechanismList")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SLOT_ID, C.CK_MECHANISM_TYPE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(slotID, pMechanismList, pulCount)
}

//export C_GetObjectSize
func C_GetObjectSize(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pulSize C.CK_ULONG_PTR /*pusSize C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_GetObjectSize")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, hObject, pulSize)
}

//export C_GetOperationState
func C_GetOperationState(hSession C.CK_SESSION_HANDLE, pOperationState C.CK_BYTE_PTR, pulOperationStateLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	symbol := getDynamicLibrarySymbol("C_GetOperationState")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pOperationState, pulOperationStateLen)
}

//export C_GetSessionInfo
func C_GetSessionInfo(hSession C.CK_SESSION_HANDLE, pInfo C.CK_SESSION_INFO_PTR) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_GetSessionInfo")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_SESSION_INFO_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pInfo)
}

//export C_GetSlotInfo
func C_GetSlotInfo(slotID C.CK_SLOT_ID, pInfo C.CK_SLOT_INFO_PTR) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_GetSlotInfo")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SLOT_ID, C.CK_SLOT_INFO_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(slotID, pInfo)
}

//export C_GetSlotList
func C_GetSlotList(tokenPresent C.CK_BBOOL, pSlotList C.CK_SLOT_ID_PTR, pulCount C.CK_ULONG_PTR /*pusCount C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_GetSlotList")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_BBOOL, C.CK_SLOT_ID_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(tokenPresent, pSlotList, pulCount)
}

//export C_GetTokenInfo
func C_GetTokenInfo(slotID C.CK_SLOT_ID, pInfo C.CK_TOKEN_INFO_PTR) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_GetTokenInfo")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SLOT_ID, C.CK_TOKEN_INFO_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(slotID, pInfo)
}

//export C_Initialize
func C_Initialize(pInitArgs C.CK_VOID_PTR /*pReserved C.CK_VOID_PTR (v1.0,v2.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_Initialize")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_VOID_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(pInitArgs)
}

//export C_InitPIN
func C_InitPIN(hSession C.CK_SESSION_HANDLE, pPin C.CK_UTF8CHAR_PTR /*pPin C.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)*/, ulPinLen C.CK_ULONG /*usPinLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_InitPIN")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_UTF8CHAR_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pPin, ulPinLen)
}

//export C_InitToken
func C_InitToken(slotID C.CK_SLOT_ID, pPin C.CK_UTF8CHAR_PTR /*pPin C.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)*/, ulPinLen C.CK_ULONG /*usPinLen C.CK_USHORT (v1.0)*/, pLabel C.CK_UTF8CHAR_PTR /*pLabel C.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_InitToken")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SLOT_ID, C.CK_UTF8CHAR_PTR, C.CK_ULONG, C.CK_UTF8CHAR_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(slotID, pPin, ulPinLen, pLabel)
}

//export C_Login
func C_Login(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_UTF8CHAR_PTR /*pPin C.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)*/, ulPinLen C.CK_ULONG /*usPinLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_Login")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_USER_TYPE, C.CK_UTF8CHAR_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, userType, pPin, ulPinLen)
}

//export C_LoginUser
func C_LoginUser(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG, pUsername C.CK_UTF8CHAR_PTR, ulUsernameLen C.CK_ULONG) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_LoginUser")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_USER_TYPE, C.CK_UTF8CHAR_PTR, C.CK_ULONG, C.CK_UTF8CHAR_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, userType, pPin, ulPinLen, pUsername, ulUsernameLen)
}

//export C_Logout
func C_Logout(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_Logout")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession)
}

//export C_MessageDecryptFinal
func C_MessageDecryptFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_MessageDecryptFinal")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession)
}

//export C_MessageDecryptInit
func C_MessageDecryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_MessageDecryptInit")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pMechanism, hKey)
}

//export C_MessageEncryptFinal
func C_MessageEncryptFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_MessageEncryptFinal")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession)
}

//export C_MessageEncryptInit
func C_MessageEncryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_MessageEncryptInit")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pMechanism, hKey)
}

//export C_MessageSignFinal
func C_MessageSignFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_MessageSignFinal")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession)
}

//export C_MessageSignInit
func C_MessageSignInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_MessageSignInit")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pMechanism, hKey)
}

//export C_MessageVerifyFinal
func C_MessageVerifyFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_MessageVerifyFinal")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession)
}

//export C_MessageVerifyInit
func C_MessageVerifyInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_MessageVerifyInit")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pMechanism, hKey)
}

//export C_OpenSession
func C_OpenSession(slotID C.CK_SLOT_ID, flags C.CK_FLAGS, pApplication C.CK_VOID_PTR, Notify C.CK_NOTIFY /*CK_RV (*Notify)(CK_SESSION_HANDLE hSession, C.CK_NOTIFICATION event, C.CK_VOID_PTR pApplication) (v1.0)*/, phSession C.CK_SESSION_HANDLE_PTR) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_OpenSession")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SLOT_ID, C.CK_FLAGS, C.CK_VOID_PTR, C.CK_NOTIFY, C.CK_SESSION_HANDLE_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(slotID, flags, pApplication, Notify, phSession)
}

//export C_SeedRandom
func C_SeedRandom(hSession C.CK_SESSION_HANDLE, pSeed C.CK_BYTE_PTR, ulSeedLen C.CK_ULONG /*usSeedLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_SeedRandom")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pSeed, ulSeedLen)
}

//export C_SessionCancel
func C_SessionCancel(hSession C.CK_SESSION_HANDLE, flags C.CK_FLAGS) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_SessionCancel")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_FLAGS) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, flags)
}

//export C_SetAttributeValue
func C_SetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_SetAttributeValue")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE, C.CK_ATTRIBUTE_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, hObject, pTemplate, ulCount)
}

//export C_SetOperationState
func C_SetOperationState(hSession C.CK_SESSION_HANDLE, pOperationState C.CK_BYTE_PTR, ulOperationStateLen C.CK_ULONG, hEncryptionKey C.CK_OBJECT_HANDLE, hAuthenticationKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v2.0
	symbol := getDynamicLibrarySymbol("C_SetOperationState")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE, C.CK_OBJECT_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey)
}

//export C_SetPIN
func C_SetPIN(hSession C.CK_SESSION_HANDLE, pOldPin C.CK_UTF8CHAR_PTR /*pOldPin C.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)*/, ulOldLen C.CK_ULONG /*usOldLen C.CK_USHORT (v1.0)*/, pNewPin C.CK_UTF8CHAR_PTR /*pNewPin C.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)*/, ulNewLen C.CK_ULONG /*usNewLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_SetPIN")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_UTF8CHAR_PTR, C.CK_ULONG, C.CK_UTF8CHAR_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen)
}

//export C_Sign
func C_Sign(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR /*pusSignatureLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_Sign")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pData, ulDataLen, pSignature, pulSignatureLen)
}

//export C_SignEncryptUpdate
func C_SignEncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	symbol := getDynamicLibrarySymbol("C_SignEncryptUpdate")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen)
}

//export C_SignFinal
func C_SignFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR /*pusSignatureLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_SignFinal")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pSignature, pulSignatureLen)
}

//export C_SignInit
func C_SignInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_SignInit")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pMechanism, hKey)
}

//export C_SignMessage
func C_SignMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_SignMessage")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pParameter, ulParameterLen, pData, ulDataLen, pSignature, pulSignatureLen)
}

//export C_SignMessageBegin
func C_SignMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_SignMessageBegin")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pParameter, ulParameterLen)
}

//export C_SignMessageNext
func C_SignMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pDataPart C.CK_BYTE_PTR, ulDataPartLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_SignMessageNext")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pParameter, ulParameterLen, pDataPart, ulDataPartLen, pSignature, pulSignatureLen)
}

//export C_SignRecover
func C_SignRecover(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR /*pusSignatureLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_SignRecover")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pData, ulDataLen, pSignature, pulSignatureLen)
}

//export C_SignRecoverInit
func C_SignRecoverInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_SignRecoverInit")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pMechanism, hKey)
}

//export C_SignUpdate
func C_SignUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG /*usPartLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_SignUpdate")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pPart, ulPartLen)
}

//export C_UnwrapKey
func C_UnwrapKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hUnwrappingKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, ulWrappedKeyLen C.CK_ULONG /*usWrappedKeyLen C.CK_USHORT (v1.0)*/, pTemplate C.CK_ATTRIBUTE_PTR, ulAttributeCount C.CK_ULONG /*usAttributeCount C.CK_USHORT (v1.0)*/, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_UnwrapKey")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey)
}

//export C_Verify
func C_Verify(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG /*usSignatureLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_Verify")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pData, ulDataLen, pSignature, ulSignatureLen)
}

//export C_VerifyFinal
func C_VerifyFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG /*usSignatureLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_VerifyFinal")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pSignature, ulSignatureLen)
}

//export C_VerifyInit
func C_VerifyInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_VerifyInit")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pMechanism, hKey)
}

//export C_VerifyMessage
func C_VerifyMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_VerifyMessage")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pParameter, ulParameterLen, pData, ulDataLen, pSignature, ulSignatureLen)
}

//export C_VerifyMessageBegin
func C_VerifyMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_VerifyMessageBegin")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pParameter, ulParameterLen)
}

//export C_VerifyMessageNext
func C_VerifyMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pDataPart C.CK_BYTE_PTR, ulDataPartLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) C.CK_RV { // Since v3.0
	symbol := getDynamicLibrarySymbol("C_VerifyMessageNext")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pParameter, ulParameterLen, pDataPart, ulDataPartLen, pSignature, ulSignatureLen)
}

//export C_VerifyRecover
func C_VerifyRecover(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG /*usSignatureLen C.CK_USHORT (v1.0)*/, pData C.CK_BYTE_PTR, pulDataLen C.CK_ULONG_PTR /*pusDataLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_VerifyRecover")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pSignature, ulSignatureLen, pData, pulDataLen)
}

//export C_VerifyRecoverInit
func C_VerifyRecoverInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_VerifyRecoverInit")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pMechanism, hKey)
}

//export C_VerifyUpdate
func C_VerifyUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG /*usPartLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_VerifyUpdate")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pPart, ulPartLen)
}

//export C_WaitForSlotEvent
func C_WaitForSlotEvent(flags C.CK_FLAGS, pSlot C.CK_SLOT_ID_PTR, pReserved C.CK_VOID_PTR) C.CK_RV { // Since v2.01
	symbol := getDynamicLibrarySymbol("C_WaitForSlotEvent")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_FLAGS, C.CK_SLOT_ID_PTR, C.CK_VOID_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(flags, pSlot, pReserved)
}

//export C_WrapKey
func C_WrapKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hWrappingKey C.CK_OBJECT_HANDLE, hKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, pulWrappedKeyLen C.CK_ULONG_PTR /*pusWrappedKeyLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	symbol := getDynamicLibrarySymbol("C_WrapKey")
	if symbol == 0 {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE, C.CK_OBJECT_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	purego.RegisterFunc(&function, symbol)
	return function(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen)
}
