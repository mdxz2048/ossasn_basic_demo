#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ossasn1.h"
#include "ltev-csae-157-2020-defs.h"

// 错误处理函数
static int report_error(OssGlobal *world, void *decoded_data, int pdu_num, char *where, int retcode, ossBoolean has_errmsg, ossBoolean do_exit)
{
    char *msg;

    if (!retcode)
        return 0;

    ossPrint(world, "\nAn error happened\n  Error origin: %s\n  Error code: %d\n", where, retcode);

    if (world && has_errmsg)
    {
        msg = ossGetErrMsg(world);
        if (msg && *msg)
            ossPrint(world, "  Error text: '%s'\n", msg);
    }

    if (NULL != (msg = ossDescribeReturnCode(world, retcode)))
        ossPrint(world, "  Error description: '%s'\n", msg);

    if (do_exit)
    {
        if (decoded_data)
            ossFreePDU(world, pdu_num, decoded_data);
        ossterm(world);
        exit(1);
    }

    return retcode;
}

// 填充 RTCM 消息
void fill_rtcm_message(asnRTCMmsg *rtcm_msg, unsigned short rtcmID, unsigned char *payload, unsigned short payload_len)
{
    memset(rtcm_msg, 0, sizeof(asnRTCMmsg));

    rtcm_msg->rev = 1; // 假设使用 RTCM 修订版 1
    rtcm_msg->bit_mask |= asnrev_present;

    rtcm_msg->rtcmID = rtcmID;
    rtcm_msg->bit_mask |= asnrtcmID_present;

    rtcm_msg->payload.length = payload_len;
    rtcm_msg->payload.value = (unsigned char *)malloc(payload_len);
    if (!rtcm_msg->payload.value)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    memcpy(rtcm_msg->payload.value, payload, payload_len);
}

// 填充 RTCM corrections
void fill_rtcm_corrections(asnRTCMcorrections *rtcm_corrections)
{
    memset(rtcm_corrections, 0, sizeof(asnRTCMcorrections));

    rtcm_corrections->msgCnt = 1; // 假设 message count 为 1

    unsigned char payload1[] = {0x01, 0x02, 0x03, 0x04};
    unsigned char payload2[] = {0x05, 0x06, 0x07, 0x08};

    asnRTCMmsg rtcm_msg1;
    fill_rtcm_message(&rtcm_msg1, 1001, payload1, sizeof(payload1));

    asnRTCMmsg rtcm_msg2;
    fill_rtcm_message(&rtcm_msg2, 1002, payload2, sizeof(payload2));

    // 添加第一个 RTCM 消息到链表
    rtcm_corrections->corrections = (struct asn_seqof8 *)malloc(sizeof(struct asn_seqof8));
    if (!rtcm_corrections->corrections)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    rtcm_corrections->corrections->value = rtcm_msg1;
    rtcm_corrections->corrections->next = NULL;

    // 添加第二个 RTCM 消息到链表
    struct asn_seqof8 *second = (struct asn_seqof8 *)malloc(sizeof(struct asn_seqof8));
    if (!second)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    second->value = rtcm_msg2;
    second->next = NULL;

    rtcm_corrections->corrections->next = second;
}

// 编码并打印 RTCM corrections
void encode_and_print_rtcm_corrections(OssGlobal *world, asnRTCMcorrections *rtcm_corrections)
{
    OssBuf output;
    int retcode;
    int pdu_num = asnRTCMcorrections_PDU;

    // 初始化 OSS 编码/解码环境
    if ((retcode = ossinit(world, ltev_csae_157_2020_defs)) != 0)
    {
        report_error(NULL, NULL, 0, "ossinit()", retcode, TRUE, TRUE);
        return;
    }

    // 动态分配足够大的缓冲区用于编码
    output.value = NULL;
    output.length = 0;

    // 先尝试编码以确定所需的缓冲区大小
    retcode = ossEncode(world, pdu_num, rtcm_corrections, &output);
    if (retcode == 0)
    {
        if (output.length > 0)
        {
            // 分配所需大小的缓冲区
            output.value = (unsigned char *)malloc(output.length);
            if (!output.value)
            {
                fprintf(stderr, "Memory allocation failed\n");
                ossterm(world);
                exit(1);
            }
            // 再次编码到新分配的缓冲区
            retcode = ossEncode(world, pdu_num, rtcm_corrections, &output);
        }
    }

    if (retcode != 0)
    {
        report_error(world, rtcm_corrections, pdu_num, "ossEncode()", retcode, TRUE, TRUE);
        return;
    }

    // 打印编码后的字节流
    printf("Encoded RTCM Corrections (UPER):\n");
    for (size_t i = 0; i < output.length; i++)
    {
        printf("%02X", output.value[i]);
    }
    printf("\n");

    // 使用 ossPrintJSON 将编码的字节流输出为 JSON 格式
    // 使用 ossPrintPDU 打印解码后的数据结构
    void *decoded_data = NULL;
    retcode = ossDecode(world, &pdu_num, &output, &decoded_data);
    if (retcode != 0)
    {
        report_error(world, NULL, pdu_num, "ossDecode()", retcode, TRUE, TRUE);
        return;
    }

    ossPrintPDU(world, pdu_num, decoded_data);

    // 释放编码数据占用的内存
    ossFreeBuf(world, output.value);
    ossFreePDU(world, pdu_num, decoded_data);

    // 终止 OSS 环境
    ossterm(world);
}

// 通用解码并打印 ASN.1 数据
void decode_and_print_asn1_data(OssGlobal *world, const char *uper_hex_string, int pdu_num)
{
    OssBuf encoded_buf;
    int retcode;

    // 初始化 OSS 编码/解码环境
    if ((retcode = ossinit(world, ltev_csae_157_2020_defs)) != 0)
    {
        report_error(NULL, NULL, 0, "ossinit()", retcode, TRUE, TRUE);
        return;
    }

    // 将UPER字符串转换为二进制数据
    size_t hex_len = strlen(uper_hex_string);
    encoded_buf.length = hex_len / 2;
    encoded_buf.value = (unsigned char *)malloc(encoded_buf.length);
    if (!encoded_buf.value)
    {
        fprintf(stderr, "Memory allocation failed\n");
        ossterm(world);
        exit(1);
    }

    for (size_t i = 0; i < encoded_buf.length; i++)
    {
        sscanf(uper_hex_string + 2 * i, "%2hhx", &encoded_buf.value[i]);
    }

    // 解码二进制数据
    void *decoded_data = NULL;
    retcode = ossDecode(world, &pdu_num, &encoded_buf, &decoded_data);
    if (retcode != 0)
    {
        report_error(world, NULL, pdu_num, "ossDecode()", retcode, TRUE, TRUE);
        return;
    }

    // 使用 ossPrintPDU 打印解码后的数据结构
    printf("Decoded ASN.1 Data:\n");
    ossPrintPDU(world, pdu_num, decoded_data);

    // 释放解码数据占用的内存
    ossFreePDU(world, pdu_num, decoded_data);
    ossFreeBuf(world, encoded_buf.value);

    // 终止 OSS 环境
    ossterm(world);
}

int main()
{
    asnRTCMcorrections rtcm_corrections;
    OssGlobal world;

    // 填充 RTCM corrections
    fill_rtcm_corrections(&rtcm_corrections);

    // 编码并打印 RTCM corrections
    encode_and_print_rtcm_corrections(&world, &rtcm_corrections);

    // 这里你可以贴入你要解码的UPER编码字符串和对应的PDU类型
    const char *uper_hex_string = "0381024003802a002569c6660686060606d178788599ca95927f4dc273800000001f41f41fdfffef8004960fa1e050400040016f000213f0c40e6e6b8042e30dc4442921ce8440b8c8663739974341c7bbd0c7d078a8e17920ec358683b43da26c8d167f3f4d300607b491b31fed4e56634d778265b0148d06a78a1e96f45d6e94ec49898ec029";
    int pdu_num = asnMessageTypes_OSET; // 你可以根据实际需要设置PDU类型

    // 解码并打印 ASN.1 数据
    decode_and_print_asn1_data(&world, uper_hex_string, pdu_num);

    return 0;
}
