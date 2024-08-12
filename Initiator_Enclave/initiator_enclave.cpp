#include "initiator_enclave_t.h"
#include <sgx_trts.h>
#include <sgx_report.h>
#include <sgx_utils.h>
#include <string.h>
#include <stdlib.h>
#include <string>

/* LAv2を使用。この指定により、sgx_dh_*系のLA関連のAPIが、
 * 内部でLAv2用のものに置き換えられ、透過的にLAv2を利用できる */
#define SGX_USE_LAv2_INITIATOR
#include <sgx_dh.h>

#define MRENCLAVE_CHECK 1 // Responder EnclaveのMRENCLAVE同一性検証実行フラグ
#define MRENCLAVE_DEBUG 1

/* LAに関連する変数を格納 */
namespace InitiatorLAParams
{
    sgx_dh_session_t session;
    sgx_key_128bit_t aek;
}


/* Responderに求める同一性情報のハードコーディング */
namespace IdentityRequest
{
    /* ResponderのMRENCLAVEは、LAの片方向性により検証はしない */
    sgx_measurement_t mr_signer = {
        0xfd, 0x9c, 0x50, 0x01, 0x42, 0x64, 0x13, 0x9a, 
        0x83, 0x01, 0xab, 0x5d, 0x9e, 0x78, 0x4e, 0x7d, 
        0x97, 0xa8, 0x64, 0x73, 0x33, 0x64, 0x4e, 0x81, 
        0x2a, 0x36, 0x11, 0x6f, 0x87, 0xd5, 0xcc, 0x99
    };

    sgx_prod_id_t isv_prod_id = 0;
    sgx_isv_svn_t isv_svn = 0;
}


/* デバッグ用: uint8_tのarrayを文字列にする */
void uint8_array_to_char_array(const uint8_t* data, size_t length, char* output) {
    const char hex_chars[] = "0123456789abcdef";
    size_t output_index = 0;
    
    for (size_t i = 0; i < length; ++i) {
        output[output_index++] = hex_chars[data[i] >> 4];
        output[output_index++] = hex_chars[data[i] & 0xF];
        output[output_index++] = ' ';
    }
    
    if (output_index > 0) {
        output_index--;
    }
    
    output[output_index] = '\0';
}


/* uint8_tのarrayを逆順にする */
void reverse_array(uint8_t* arr, size_t size) {
    size_t left = 0;
    size_t right = size - 1;

    while (left < right) {
        uint8_t temp = arr[left];
        arr[left] = arr[right];
        arr[right] = temp;
        ++left;
        --right;
    }
}


/* LAの初期化 */
int ecall_initiator_init_LA()
{
    sgx_status_t status = 
        sgx_dh_init_session(SGX_DH_SESSION_INITIATOR,
            &InitiatorLAParams::session);
    
    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to initialize initiator's LA.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return -1;
    }

    return 0;
}


/* msg1を処理しmsg2を生成 */
int ecall_initiator_proc_msg1(sgx_dh_msg1_t *msg1, sgx_dh_msg2_t *msg2)
{
    sgx_status_t status = sgx_dh_initiator_proc_msg1(
        msg1, msg2, &InitiatorLAParams::session);
    
    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to process msg1 and get msg2 in initiator.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return -1;
    }

    return 0;
}


/* msg3を処理 */
int ecall_initiator_proc_msg3(sgx_dh_msg3_t *msg3)
{
    /* Responder側の同一性情報を格納する変数 */
    sgx_dh_session_enclave_identity_t responder_identity;
    memset(&responder_identity, 0, sizeof(sgx_dh_session_enclave_identity_t));

    sgx_status_t status = sgx_dh_initiator_proc_msg3(msg3, 
        &InitiatorLAParams::session, &InitiatorLAParams::aek, &responder_identity);
    
    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to process msg3 in initiator.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return -1;
    }

    /* 同一性情報の検証 */
    int res = 0;

    /* MRENCLAVE */
    if (MRENCLAVE_CHECK)
    {
        sgx_report_t report;
        sgx_status_t status = sgx_create_report(NULL, NULL, &report);

        if (status != SGX_SUCCESS)
        {
            const char *message = "Failed to create Report of Initiator Enclave.";
            ocall_print(message, 2); //2はエラーログである事を表す
            ocall_print_status(status);
            return -1;
        }

        // KSSによりResponder EnclaveのMRENCLAVEをXMLから取得
        uint8_t *mr_enclave = new uint8_t[32]();
        memcpy(mr_enclave, report.body.isv_ext_prod_id, 16);
        memcpy(mr_enclave + 16, report.body.isv_family_id, 16);
        reverse_array(mr_enclave, 32); //　なぜか配列が逆順になってしまうため

        if (MRENCLAVE_DEBUG)
        {
            const char *message_kss = "MRENCLAVE obtained by KSS";
            char *buffer = new char[32 * 3 + 1]();
            uint8_array_to_char_array(mr_enclave, 32, buffer);
            ocall_print(message_kss, 1);
            ocall_print(buffer, 1);

            const char *message_msg3 = "MRENCLAVE obtained by msg3";
            uint8_t* response_mr_enclave = (uint8_t*)&responder_identity.mr_enclave;
            uint8_array_to_char_array(response_mr_enclave, 32, buffer);
            ocall_print(message_msg3, 1);
            ocall_print(buffer, 1);
        }

        res = memcmp(&responder_identity.mr_enclave, mr_enclave, 32);

        if (res)
        {
            const char *message = "MRENCLAVE of Responder Enclave mismatched.";
            ocall_print(message, 2); //2はエラーログである事を表す
            ocall_print_status(status);
            return -1;
        }
        const char *message = "Initiator Enclave's MRENCLAVE is successfully verified.";
        ocall_print(message, 1);
    }

    /* MRSIGNER */
    res = memcmp(&responder_identity.mr_signer, &IdentityRequest::mr_signer, 32);

    if(res)
    {
        const char *message = "MRSIGNER of Responder Enclave mismatched.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return -1;
    }

    /* ISV ProdID */
    if(responder_identity.isv_prod_id != IdentityRequest::isv_prod_id)
    {
        const char *message = "ISV ProdID of Responder Enclave mismatched.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return -1;
    }

    /* ISVSVN */
    if(responder_identity.isv_svn < IdentityRequest::isv_svn)
    {
        const char *message = "Insufficient ISVSVN of Responder Enclave.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return -1;
    }

    return 0;
}


/* Responderから受け取った2値の平均を計算し標準出力 */
int ecall_initiator_calc_average(uint8_t *value1, 
    uint8_t *value2, uint8_t *value1_iv, uint8_t *value2_iv, 
    uint8_t *value1_tag, uint8_t *value2_tag)
{
    sgx_status_t status;

    /* ヌル終端分も確保 */
    char *plain1 = new char[5]();
    char *plain2 = new char[5]();

    status = sgx_rijndael128GCM_decrypt(&InitiatorLAParams::aek,
        value1, 4, (uint8_t*)plain1, value1_iv, 12, NULL, 0, 
        (sgx_aes_gcm_128bit_tag_t*)value1_tag);

    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to decrypt value1.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return -1;
    }

    status = sgx_rijndael128GCM_decrypt(&InitiatorLAParams::aek,
        value2, 4, (uint8_t*)plain2, value2_iv, 12, NULL, 0, 
        (sgx_aes_gcm_128bit_tag_t*)value2_tag);

    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to decrypt value2.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return -1;
    }

    int plain1_int = atoi(plain1);
    int plain2_int = atoi(plain2);

    ocall_print(std::to_string((plain1_int + plain2_int)/2).c_str(), 1);

    delete[] plain1;
    delete[] plain2;

    return 0;
}

