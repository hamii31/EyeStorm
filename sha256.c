/*
 * sha256.c  --  SHA-256 helpers via Windows CNG (bcrypt.dll)
 *
 * Uses BCRYPT_SHA256_ALGORITHM -- no external deps, always present on Win10+.
 */

#include "sysmon.h"
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

 /* -- hash a file on disk --------------------------------------------------- */
BOOL sha256_file(const char* path, BYTE out[SHA256_LEN])
{
    BCRYPT_ALG_HANDLE  hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    HANDLE             hFile = INVALID_HANDLE_VALUE;
    BOOL               ok = FALSE;
    DWORD              read;
    DWORD              hashObjSize = 0, cbData = 0;
    PBYTE              hashObj = NULL;
    /* Heap-allocate the read buffer -- keeping 64 KB on the stack pushes the
     * call-chain stack depth over the MSVC C6262 threshold (3.3 MB total).  */
    BYTE* chunk = NULL;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
        NULL, 0) != 0)
        goto done;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        (PBYTE)&hashObjSize, sizeof(hashObjSize),
        &cbData, 0) != 0)
        goto done;

    hashObj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, hashObjSize);
    if (!hashObj) goto done;

    chunk = (BYTE*)HeapAlloc(GetProcessHeap(), 0, 65536);
    if (!chunk) goto done;

    if (BCryptCreateHash(hAlg, &hHash, hashObj, hashObjSize,
        NULL, 0, 0) != 0)
        goto done;

    hFile = CreateFileA(path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) goto done;

    while (ReadFile(hFile, chunk, 65536, &read, NULL) && read > 0) {
        if (BCryptHashData(hHash, chunk, read, 0) != 0) goto done;
    }

    if (BCryptFinishHash(hHash, out, SHA256_LEN, 0) != 0) goto done;
    ok = TRUE;

done:
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (hHash)   BCryptDestroyHash(hHash);
    if (hAlg)    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hashObj) HeapFree(GetProcessHeap(), 0, hashObj);
    if (chunk)   HeapFree(GetProcessHeap(), 0, chunk);
    return ok;
}

/* -- hash an in-memory buffer ---------------------------------------------- */
BOOL sha256_buf(const BYTE* data, SIZE_T len, BYTE out[SHA256_LEN])
{
    BCRYPT_ALG_HANDLE  hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BOOL               ok = FALSE;
    DWORD              hashObjSize = 0, cbData = 0;
    PBYTE              hashObj = NULL;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
        NULL, 0) != 0)
        goto done;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        (PBYTE)&hashObjSize, sizeof(hashObjSize),
        &cbData, 0) != 0)
        goto done;

    hashObj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, hashObjSize);
    if (!hashObj) goto done;

    if (BCryptCreateHash(hAlg, &hHash, hashObj, hashObjSize,
        NULL, 0, 0) != 0)
        goto done;

    /* feed in chunks to handle large buffers */
    SIZE_T remaining = len;
    const BYTE* ptr = data;
    while (remaining > 0) {
        ULONG chunk = (remaining > 0x7FFFFFFF) ? 0x7FFFFFFF : (ULONG)remaining;
        if (BCryptHashData(hHash, (PUCHAR)ptr, chunk, 0) != 0) goto done;
        ptr += chunk;
        remaining -= chunk;
    }

    if (BCryptFinishHash(hHash, out, SHA256_LEN, 0) != 0) goto done;
    ok = TRUE;

done:
    if (hHash)   BCryptDestroyHash(hHash);
    if (hAlg)    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hashObj) HeapFree(GetProcessHeap(), 0, hashObj);
    return ok;
}

/* -- convert raw bytes ? lowercase hex string ------------------------------ */
void sha256_to_hex(const BYTE in[SHA256_LEN], char out[65])
{
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < SHA256_LEN; i++) {
        out[i * 2] = hex[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[in[i] & 0xF];
    }
    out[64] = '\0';
}
