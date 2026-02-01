package main

// #include <dlfcn.h>
// #include "cgo.h"
import "C"
import "fmt"
import "os"
import "unsafe"

import "github.com/ebitengine/purego"

func main() {}

var libraryHandle unsafe.Pointer = nil
var libraryHandlePure uintptr = 0
var libraryPID int = -1
var libraryPIDPure int = -1

func getDynamicLibrary() unsafe.Pointer {
	if libraryHandle == nil || libraryPID == -1 || libraryPID != os.Getpid() {
		if libraryHandle != nil {
			C.dlclose(libraryHandle)
		}
		libraryHandle = C.dlopen(C.CString(os.Getenv("PKCS11_SUBMODULE")), C.RTLD_LAZY|C.RTLD_GLOBAL)
		if libraryHandle == nil {
			return nil
		}
		libraryPID = os.Getpid()
	}
	return libraryHandle
}

func getDynamicLibraryPure() uintptr {
	if libraryHandlePure == 0 || libraryPIDPure == -1 || libraryPIDPure != os.Getpid() {
		if libraryHandlePure != 0 {
			purego.Dlclose(libraryHandlePure)
		}
		libraryHandlePure, _ = purego.Dlopen(os.Getenv("PKCS11_SUBMODULE"), purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if libraryHandlePure == 0 {
			return 0
		}
		libraryPIDPure = os.Getpid()
	}
	return libraryHandlePure
}

func getDynamicLibrarySymbol(functionName string) any {
	lh := getDynamicLibrary()
	if lh == nil {
		return nil
	}
	return C.dlsym(lh, C.CString(functionName))
}

func registerDynamicLibrarySymbolPure(fptr any, functionName string) any {
	lh := getDynamicLibraryPure()
	if lh == 0 {
		return nil
	}
	purego.RegisterLibFunc(fptr, lh, functionName)
	return fptr
}

//export C_CancelFunction
func C_CancelFunction(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_CancelFunction")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession)
}

//export C_CloseAllSessions
func C_CloseAllSessions(slotID C.CK_SLOT_ID) C.CK_RV { // Since v1.0
	var function func(C.CK_SLOT_ID) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_CloseAllSessions")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(slotID)
}

//export C_CloseSession
func C_CloseSession(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_CloseSession")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession)
}

//export C_CopyObject
func C_CopyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/, phNewObject C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE, C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_CopyObject")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, hObject, pTemplate, ulCount, phNewObject)
}

//export C_CreateObject
func C_CreateObject(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/, phObject C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_CreateObject")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pTemplate, ulCount, phObject)
}

//export C_Decrypt
func C_Decrypt(hSession C.CK_SESSION_HANDLE, pEncryptedData C.CK_BYTE_PTR, ulEncryptedDataLen C.CK_ULONG /*usEncryptedDataLen C.CK_USHORT (v1.0)*/, pData C.CK_BYTE_PTR, pulDataLen C.CK_ULONG_PTR /*pusDataLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_Decrypt")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen)
}

//export C_DecryptDigestUpdate
func C_DecryptDigestUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_DecryptDigestUpdate")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen)
}

//export C_DecryptFinal
func C_DecryptFinal(hSession C.CK_SESSION_HANDLE, pLastPart C.CK_BYTE_PTR, pulLastPartLen C.CK_ULONG_PTR /*usLastPartLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_DecryptFinal")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pLastPart, pulLastPartLen)
}

//export C_DecryptInit
func C_DecryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_DecryptInit")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pMechanism, hKey)
}

//export C_DecryptMessage
func C_DecryptMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG, pCiphertext C.CK_BYTE_PTR, ulCiphertextLen C.CK_ULONG, pPlaintext C.CK_BYTE_PTR, pulPlaintextLen C.CK_ULONG_PTR) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_DecryptMessage")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen, pCiphertext, ulCiphertextLen, pPlaintext, pulPlaintextLen)
}

//export C_DecryptMessageBegin
func C_DecryptMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_DecryptMessageBegin")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen)
}

//export C_DecryptMessageNext
func C_DecryptMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pCiphertextPart C.CK_BYTE_PTR, ulCiphertextPartLen C.CK_ULONG, pPlaintextPart C.CK_BYTE_PTR, pulPlaintextPartLen C.CK_ULONG_PTR, flags C.CK_FLAGS) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR, C.CK_FLAGS) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_DecryptMessageNext")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pParameter, ulParameterLen, pCiphertextPart, ulCiphertextPartLen, pPlaintextPart, pulPlaintextPartLen, flags)
}

//export C_DecryptUpdate
func C_DecryptUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG /*usEncryptedPartLen C.CK_USHORT (v1.0)*/, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR /*pusPartLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_DecryptUpdate")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen)
}

//export C_DecryptVerifyUpdate
func C_DecryptVerifyUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_DecryptVerifyUpdate")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen)
}

//export C_DeriveKey
func C_DeriveKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hBaseKey C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulAttributeCount C.CK_ULONG /*usAttributeCount C.CK_USHORT (v1.0)*/, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE, C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_DeriveKey")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey)
}

//export C_DestroyObject
func C_DestroyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_DestroyObject")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, hObject)
}

//export C_Digest
func C_Digest(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pDigest C.CK_BYTE_PTR, pulDigestLen C.CK_ULONG_PTR /*pusDigestLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_Digest")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pData, ulDataLen, pDigest, pulDigestLen)
}

//export C_DigestEncryptUpdate
func C_DigestEncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_DigestEncryptUpdate")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen)
}

//export C_DigestFinal
func C_DigestFinal(hSession C.CK_SESSION_HANDLE, pDigest C.CK_BYTE_PTR, pulDigestLen C.CK_ULONG_PTR /*pusDigestLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_DigestFinal")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pDigest, pulDigestLen)
}

//export C_DigestInit
func C_DigestInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_DigestInit")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pMechanism)
}

//export C_DigestKey
func C_DigestKey(hSession C.CK_SESSION_HANDLE, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v2.0
	var function func(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_DigestKey")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, hKey)
}

//export C_DigestUpdate
func C_DigestUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG /*usPartLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_DigestUpdate")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pPart, ulPartLen)
}

//export C_Encrypt
func C_Encrypt(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pEncryptedData C.CK_BYTE_PTR, pulEncryptedDataLen C.CK_ULONG_PTR /*pusEncryptedDataLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_Encrypt")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen)
}

//export C_EncryptFinal
func C_EncryptFinal(hSession C.CK_SESSION_HANDLE, pLastEncryptedPart C.CK_BYTE_PTR, pulLastEncryptedPartLen C.CK_ULONG_PTR /*pusEncryptedPartLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_EncryptFinal")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pLastEncryptedPart, pulLastEncryptedPartLen)
}

//export C_EncryptInit
func C_EncryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_EncryptInit")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pMechanism, hKey)
}

//export C_EncryptMessage
func C_EncryptMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG, pPlaintext C.CK_BYTE_PTR, ulPlaintextLen C.CK_ULONG, pCiphertext C.CK_BYTE_PTR, pulCiphertextLen C.CK_ULONG_PTR) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_EncryptMessage")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen, pPlaintext, ulPlaintextLen, pCiphertext, pulCiphertextLen)
}

//export C_EncryptMessageBegin
func C_EncryptMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_EncryptMessageBegin")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen)
}

//export C_EncryptMessageNext
func C_EncryptMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pPlaintextPart C.CK_BYTE_PTR, ulPlaintextPartLen C.CK_ULONG, pCiphertextPart C.CK_BYTE_PTR, pulCiphertextPartLen C.CK_ULONG_PTR, flags C.CK_FLAGS) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR, C.CK_FLAGS) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_EncryptMessageNext")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pParameter, ulParameterLen, pPlaintextPart, ulPlaintextPartLen, pCiphertextPart, pulCiphertextPartLen, flags)
}

//export C_EncryptUpdate
func C_EncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG /*usPartLen C.CK_USHORT (v1.0)*/, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR /*pusEncryptedPartLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_EncryptUpdate")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen)
}

//export C_Finalize
func C_Finalize(pReserved C.CK_VOID_PTR) C.CK_RV { // Since v2.0
	var function func(C.CK_VOID_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_Finalize")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(pReserved)
}

//export C_FindObjects
func C_FindObjects(hSession C.CK_SESSION_HANDLE, phObject C.CK_OBJECT_HANDLE_PTR, ulMaxObjectCount C.CK_ULONG /*usMaxObjectCount C.CK_USHORT (v1.0)*/, pulObjectCount C.CK_ULONG_PTR /*pusObjectCount C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE_PTR, C.CK_ULONG, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_FindObjects")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, phObject, ulMaxObjectCount, pulObjectCount)
}

//export C_FindObjectsFinal
func C_FindObjectsFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v2.0
	var function func(C.CK_SESSION_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_FindObjectsFinal")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession)
}

//export C_FindObjectsInit
func C_FindObjectsInit(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_ATTRIBUTE_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_FindObjectsInit")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pTemplate, ulCount)
}

//export C_GenerateKey
func C_GenerateKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_GenerateKey")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pMechanism, pTemplate, ulCount, phKey)
}

//export C_GenerateKeyPair
func C_GenerateKeyPair(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pPublicKeyTemplate C.CK_ATTRIBUTE_PTR, ulPublicKeyAttributeCount C.CK_ULONG /*usPublicKeyAttributeCount C.CK_USHORT (v1.0)*/, pPrivateKeyTemplate C.CK_ATTRIBUTE_PTR, ulPrivateKeyAttributeCount C.CK_ULONG /*usPrivateKeyAttributeCount C.CK_USHORT (v1.0)*/, phPrivateKey C.CK_OBJECT_HANDLE_PTR, phPublicKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR, C.CK_OBJECT_HANDLE_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_GenerateKeyPair")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPrivateKey, phPublicKey)
}

//export C_GenerateRandom
func C_GenerateRandom(hSession C.CK_SESSION_HANDLE, pRandomData C.CK_BYTE_PTR, ulRandomLen C.CK_ULONG /*usRandomLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_GenerateRandom")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pRandomData, ulRandomLen)
}

//export C_GetAttributeValue
func C_GetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE, C.CK_ATTRIBUTE_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_GetAttributeValue")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, hObject, pTemplate, ulCount)
}

//export C_GetFunctionList
func C_GetFunctionList(ppFunctionList C.CK_FUNCTION_LIST_PTR_PTR) C.CK_RV { // Since v2.0
	var function func(C.CK_FUNCTION_LIST_PTR_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_GetFunctionList")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(ppFunctionList)
}

//export C_GetFunctionStatus
func C_GetFunctionStatus(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_GetFunctionStatus")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession)
}

//export C_GetInfo
func C_GetInfo(pInfo C.CK_INFO_PTR) C.CK_RV { // Since v1.0
	var function func(C.CK_INFO_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_GetInfo")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(pInfo)
}

//export C_GetInterface
func C_GetInterface(pInterfaceName C.CK_UTF8CHAR_PTR, pVersion C.CK_VERSION_PTR, ppInterface C.CK_INTERFACE_PTR_PTR, flags C.CK_FLAGS) C.CK_RV { // Since v3.0
	var function func(C.CK_UTF8CHAR_PTR, C.CK_VERSION_PTR, C.CK_INTERFACE_PTR_PTR, C.CK_FLAGS) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_GetInterface")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(pInterfaceName, pVersion, ppInterface, flags)
}

//export C_GetInterfaceList
func C_GetInterfaceList(pInterfaceList C.CK_INTERFACE_PTR, pulCount C.CK_ULONG_PTR) C.CK_RV { // Since v3.0
	var function func(C.CK_INTERFACE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_GetInterfaceList")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(pInterfaceList, pulCount)
}

//export C_GetMechanismInfo
func C_GetMechanismInfo(slotID C.CK_SLOT_ID, _type C.CK_MECHANISM_TYPE, pInfo C.CK_MECHANISM_INFO_PTR) C.CK_RV { // Since v1.0
	var function func(C.CK_SLOT_ID, C.CK_MECHANISM_TYPE, C.CK_MECHANISM_INFO_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_GetMechanismInfo")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(slotID, _type, pInfo)
}

//export C_GetMechanismList
func C_GetMechanismList(slotID C.CK_SLOT_ID, pMechanismList C.CK_MECHANISM_TYPE_PTR, pulCount C.CK_ULONG_PTR /*pusCount C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SLOT_ID, C.CK_MECHANISM_TYPE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_GetMechanismList")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(slotID, pMechanismList, pulCount)
}

//export C_GetObjectSize
func C_GetObjectSize(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pulSize C.CK_ULONG_PTR /*pusSize C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_GetObjectSize")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, hObject, pulSize)
}

//export C_GetOperationState
func C_GetOperationState(hSession C.CK_SESSION_HANDLE, pOperationState C.CK_BYTE_PTR, pulOperationStateLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_GetOperationState")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pOperationState, pulOperationStateLen)
}

//export C_GetSessionInfo
func C_GetSessionInfo(hSession C.CK_SESSION_HANDLE, pInfo C.CK_SESSION_INFO_PTR) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_SESSION_INFO_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_GetSessionInfo")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pInfo)
}

//export C_GetSlotInfo
func C_GetSlotInfo(slotID C.CK_SLOT_ID, pInfo C.CK_SLOT_INFO_PTR) C.CK_RV { // Since v1.0
	var function func(C.CK_SLOT_ID, C.CK_SLOT_INFO_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_GetSlotInfo")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(slotID, pInfo)
}

//export C_GetSlotList
func C_GetSlotList(tokenPresent C.CK_BBOOL, pSlotList C.CK_SLOT_ID_PTR, pulCount C.CK_ULONG_PTR /*pusCount C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_BBOOL, C.CK_SLOT_ID_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_GetSlotList")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(tokenPresent, pSlotList, pulCount)
}

//export C_GetTokenInfo
func C_GetTokenInfo(slotID C.CK_SLOT_ID, pInfo C.CK_TOKEN_INFO_PTR) C.CK_RV { // Since v1.0
	var function func(C.CK_SLOT_ID, C.CK_TOKEN_INFO_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_GetTokenInfo")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(slotID, pInfo)
}

//export C_Initialize
func C_Initialize(pInitArgs C.CK_VOID_PTR /*pReserved C.CK_VOID_PTR (v1.0,v2.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_VOID_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_Initialize")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(pInitArgs)
}

//export C_InitPIN
func C_InitPIN(hSession C.CK_SESSION_HANDLE, pPin C.CK_UTF8CHAR_PTR /*pPin C.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)*/, ulPinLen C.CK_ULONG /*usPinLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_UTF8CHAR_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_InitPIN")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pPin, ulPinLen)
}

//export C_InitToken
func C_InitToken(slotID C.CK_SLOT_ID, pPin C.CK_UTF8CHAR_PTR /*pPin C.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)*/, ulPinLen C.CK_ULONG /*usPinLen C.CK_USHORT (v1.0)*/, pLabel C.CK_UTF8CHAR_PTR /*pLabel C.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SLOT_ID, C.CK_UTF8CHAR_PTR, C.CK_ULONG, C.CK_UTF8CHAR_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_InitToken")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(slotID, pPin, ulPinLen, pLabel)
}

//export C_Login
func C_Login(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_UTF8CHAR_PTR /*pPin C.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)*/, ulPinLen C.CK_ULONG /*usPinLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_USER_TYPE, C.CK_UTF8CHAR_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_Login")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, userType, pPin, ulPinLen)
}

//export C_LoginUser
func C_LoginUser(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG, pUsername C.CK_UTF8CHAR_PTR, ulUsernameLen C.CK_ULONG) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE, C.CK_USER_TYPE, C.CK_UTF8CHAR_PTR, C.CK_ULONG, C.CK_UTF8CHAR_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_LoginUser")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, userType, pPin, ulPinLen, pUsername, ulUsernameLen)
}

//export C_Logout
func C_Logout(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_Logout")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession)
}

//export C_MessageDecryptFinal
func C_MessageDecryptFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_MessageDecryptFinal")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession)
}

//export C_MessageDecryptInit
func C_MessageDecryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_MessageDecryptInit")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pMechanism, hKey)
}

//export C_MessageEncryptFinal
func C_MessageEncryptFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_MessageEncryptFinal")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession)
}

//export C_MessageEncryptInit
func C_MessageEncryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_MessageEncryptInit")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pMechanism, hKey)
}

//export C_MessageSignFinal
func C_MessageSignFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_MessageSignFinal")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession)
}

//export C_MessageSignInit
func C_MessageSignInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_MessageSignInit")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pMechanism, hKey)
}

//export C_MessageVerifyFinal
func C_MessageVerifyFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_MessageVerifyFinal")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession)
}

//export C_MessageVerifyInit
func C_MessageVerifyInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_MessageVerifyInit")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pMechanism, hKey)
}

//export C_OpenSession
func C_OpenSession(slotID C.CK_SLOT_ID, flags C.CK_FLAGS, pApplication C.CK_VOID_PTR, Notify C.CK_NOTIFY /*CK_RV (*Notify)(CK_SESSION_HANDLE hSession, C.CK_NOTIFICATION event, C.CK_VOID_PTR pApplication) (v1.0)*/, phSession C.CK_SESSION_HANDLE_PTR) C.CK_RV { // Since v1.0
	var function func(C.CK_SLOT_ID, C.CK_FLAGS, C.CK_VOID_PTR, C.CK_NOTIFY, C.CK_SESSION_HANDLE_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_OpenSession")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(slotID, flags, pApplication, Notify, phSession)
}

//export C_SeedRandom
func C_SeedRandom(hSession C.CK_SESSION_HANDLE, pSeed C.CK_BYTE_PTR, ulSeedLen C.CK_ULONG /*usSeedLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_SeedRandom")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pSeed, ulSeedLen)
}

//export C_SessionCancel
func C_SessionCancel(hSession C.CK_SESSION_HANDLE, flags C.CK_FLAGS) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE, C.CK_FLAGS) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_SessionCancel")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, flags)
}

//export C_SetAttributeValue
func C_SetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE, C.CK_ATTRIBUTE_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_SetAttributeValue")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, hObject, pTemplate, ulCount)
}

//export C_SetOperationState
func C_SetOperationState(hSession C.CK_SESSION_HANDLE, pOperationState C.CK_BYTE_PTR, ulOperationStateLen C.CK_ULONG, hEncryptionKey C.CK_OBJECT_HANDLE, hAuthenticationKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v2.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE, C.CK_OBJECT_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_SetOperationState")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey)
}

//export C_SetPIN
func C_SetPIN(hSession C.CK_SESSION_HANDLE, pOldPin C.CK_UTF8CHAR_PTR /*pOldPin C.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)*/, ulOldLen C.CK_ULONG /*usOldLen C.CK_USHORT (v1.0)*/, pNewPin C.CK_UTF8CHAR_PTR /*pNewPin C.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)*/, ulNewLen C.CK_ULONG /*usNewLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_UTF8CHAR_PTR, C.CK_ULONG, C.CK_UTF8CHAR_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_SetPIN")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen)
}

//export C_Sign
func C_Sign(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR /*pusSignatureLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_Sign")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pData, ulDataLen, pSignature, pulSignatureLen)
}

//export C_SignEncryptUpdate
func C_SignEncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_SignEncryptUpdate")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen)
}

//export C_SignFinal
func C_SignFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR /*pusSignatureLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_SignFinal")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pSignature, pulSignatureLen)
}

//export C_SignInit
func C_SignInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_SignInit")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pMechanism, hKey)
}

//export C_SignMessage
func C_SignMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_SignMessage")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pParameter, ulParameterLen, pData, ulDataLen, pSignature, pulSignatureLen)
}

//export C_SignMessageBegin
func C_SignMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_SignMessageBegin")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pParameter, ulParameterLen)
}

//export C_SignMessageNext
func C_SignMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pDataPart C.CK_BYTE_PTR, ulDataPartLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_SignMessageNext")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pParameter, ulParameterLen, pDataPart, ulDataPartLen, pSignature, pulSignatureLen)
}

//export C_SignRecover
func C_SignRecover(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR /*pusSignatureLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_SignRecover")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pData, ulDataLen, pSignature, pulSignatureLen)
}

//export C_SignRecoverInit
func C_SignRecoverInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_SignRecoverInit")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pMechanism, hKey)
}

//export C_SignUpdate
func C_SignUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG /*usPartLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_SignUpdate")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pPart, ulPartLen)
}

//export C_UnwrapKey
func C_UnwrapKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hUnwrappingKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, ulWrappedKeyLen C.CK_ULONG /*usWrappedKeyLen C.CK_USHORT (v1.0)*/, pTemplate C.CK_ATTRIBUTE_PTR, ulAttributeCount C.CK_ULONG /*usAttributeCount C.CK_USHORT (v1.0)*/, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_UnwrapKey")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey)
}

//export C_Verify
func C_Verify(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG /*usSignatureLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_Verify")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pData, ulDataLen, pSignature, ulSignatureLen)
}

//export C_VerifyFinal
func C_VerifyFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG /*usSignatureLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_VerifyFinal")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pSignature, ulSignatureLen)
}

//export C_VerifyInit
func C_VerifyInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_VerifyInit")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pMechanism, hKey)
}

//export C_VerifyMessage
func C_VerifyMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_VerifyMessage")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pParameter, ulParameterLen, pData, ulDataLen, pSignature, ulSignatureLen)
}

//export C_VerifyMessageBegin
func C_VerifyMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_VerifyMessageBegin")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pParameter, ulParameterLen)
}

//export C_VerifyMessageNext
func C_VerifyMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pDataPart C.CK_BYTE_PTR, ulDataPartLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) C.CK_RV { // Since v3.0
	var function func(C.CK_SESSION_HANDLE, C.CK_VOID_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_VerifyMessageNext")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pParameter, ulParameterLen, pDataPart, ulDataPartLen, pSignature, ulSignatureLen)
}

//export C_VerifyRecover
func C_VerifyRecover(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG /*usSignatureLen C.CK_USHORT (v1.0)*/, pData C.CK_BYTE_PTR, pulDataLen C.CK_ULONG_PTR /*pusDataLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_VerifyRecover")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pSignature, ulSignatureLen, pData, pulDataLen)
}

//export C_VerifyRecoverInit
func C_VerifyRecoverInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_VerifyRecoverInit")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pMechanism, hKey)
}

//export C_VerifyUpdate
func C_VerifyUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG /*usPartLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_VerifyUpdate")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pPart, ulPartLen)
}

//export C_WaitForSlotEvent
func C_WaitForSlotEvent(flags C.CK_FLAGS, pSlot C.CK_SLOT_ID_PTR, pReserved C.CK_VOID_PTR) C.CK_RV { // Since v2.01
	var function func(C.CK_FLAGS, C.CK_SLOT_ID_PTR, C.CK_VOID_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_WaitForSlotEvent")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(flags, pSlot, pReserved)
}

//export C_WrapKey
func C_WrapKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hWrappingKey C.CK_OBJECT_HANDLE, hKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, pulWrappedKeyLen C.CK_ULONG_PTR /*pusWrappedKeyLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	var function func(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE, C.CK_OBJECT_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV
	functionRV := registerDynamicLibrarySymbolPure(&function, "C_WrapKey")
	if functionRV == nil {
		fmt.Println("Failed getting symbol for this function.")
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}
	return function(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen)
}
