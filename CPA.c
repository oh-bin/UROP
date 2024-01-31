////////////////////////////////////////
//CPA 수행 코드
////////////////////////////////////////

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define TraceNumber 5000 // 총 파형 갯 수
#define PointNumber 4376 // 총 포인트 갯 수
#define PlaintextLength 16 // 평문길이
// 분석 구간 설정
#define TargetPointerlow 850 
#define TargetPointerhigh 2000
// 파형 개형을 보기 위해 저장하는 파일
#define FirstTrace ""
// 파형 수집 시 저장되는 파일(.trace)
#define Tracefile ""
// 평문 파일
#define Plaintextfile ""
// CPA 수행 시 결과에 대한 파일
#define Saveresultfile ""

//1바이트
typedef unsigned char BYTE;

//CPA를 통한 키를 저장하는 구조체
typedef struct bestkey {
    BYTE key;
    int pointnumber;
    double Largest_correlation;
    double Sec_largest_correlation;
}bestkey;

//Sbox Table(AES)
const BYTE SBox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

//Hamming weight Sbox Table
const BYTE HM_SBox[256] = {
    4, 5, 6, 6, 5, 5, 6, 4, 2, 1, 5, 4, 7, 6, 5, 5,
    4, 2, 4, 6, 6, 4, 4, 4, 5, 4, 3, 6, 4, 3, 4, 2,
    6, 7, 4, 3, 4, 6, 7, 4, 3, 4, 5, 5, 4, 4, 3, 3,
    1, 5, 3, 4, 2, 4, 2, 4, 3, 2, 1, 4, 6, 4, 4, 5,
    2, 3, 3, 3, 4, 5, 4, 2, 3, 5, 5, 5, 3, 5, 5, 2,
    4, 4, 0, 6, 1, 6, 4, 5, 4, 5, 6, 4, 3, 3, 3, 6,
    3, 7, 4, 7, 3, 4, 4, 3, 3, 6, 1, 7, 2, 4, 6, 3,
    3, 4, 1, 5, 3, 5, 3, 6, 5, 5, 5, 2, 1, 8, 6, 4,
    5, 2, 3, 5, 6, 5, 2, 4, 3, 5, 6, 5, 3, 5, 3, 5,
    2, 2, 5, 5, 2, 3, 2, 2, 3, 6, 4, 2, 6, 5, 3, 6,
    3, 3, 4, 2, 3, 2, 2, 4, 3, 5, 4, 3, 3, 4, 4, 5,
    6, 3, 5, 5, 4, 5, 4, 4, 4, 4, 5, 5, 4, 5, 5, 1,
    5, 4, 3, 4, 3, 4, 4, 4, 4, 6, 4, 5, 4, 6, 4, 3,
    3, 5, 5, 4, 2, 2, 6, 3, 3, 4, 5, 5, 3, 3, 4, 5,
    4, 5, 3, 2, 4, 5, 4, 3, 5, 4, 4, 5, 5, 4, 2, 7,
    3, 3, 3, 3, 7, 5, 2, 3, 2, 4, 4, 4, 3, 3, 6, 3
};

//HammingWeight 값을 반환
int return_HammingWeight(BYTE input)
{
    int HW = 0;
    for (int i = 0; i < 8; i++)
    {
        HW += (input >> i) & 0x01;
    }
    return HW;
}

//구현의 최적화를 위하여 Hammingweight Sbox를 만드는 함수
void makeHammingweight_Table()
{
    for (int i = 0; i < 256; i++)
    {
        printf("%d, ", return_HammingWeight(SBox[(BYTE)i]));
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
}

//그래프 파형 볼 수 있게 파형 중 1개의 결과만 저장
void tracefile_to_textfile()
{
    FILE* fpInput = fopen(Tracefile, "rb");
    FILE* fpOutput = fopen(FirstTrace, "wt");
    float buf = 0.0;

    if ((fpInput == NULL) || (fpOutput == NULL))
    {
        fprintf(stderr, "error\n");

        return 0;
    }

    fseek(fpInput, 32, SEEK_CUR);

    for (int i = 0; i < PointNumber; i++)
    {
        fread(&buf, sizeof(buf), 1, fpInput);
        fprintf(fpOutput, "%.10f\n", buf);
    }

    fclose(fpInput);
    fclose(fpOutput);
}

//CPA 수행
void CPA()
{
    FILE* PlaintextFile = fopen(Plaintextfile, "rt");
    FILE* TraceFile = fopen(Tracefile, "rb");
    FILE* resultFile = fopen(Saveresultfile, "wt");

    if ((PlaintextFile == NULL) || (TraceFile == NULL))
    {
        fprintf(stderr, "error\n");
        return;
    }

    BYTE** plaintextbuf = NULL;
    float** tracebuf = NULL;
    plaintextbuf = (BYTE**)calloc(TraceNumber, sizeof(BYTE*)); //plaintextbuf[평문 수][평문바이트 수]
    tracebuf = (float**)calloc(TraceNumber, sizeof(float*)); //tracebuf[파형 수][포인트 수]
    for (int i = 0; i < TraceNumber; i++)
    {
        plaintextbuf[i] = (BYTE*)calloc(PlaintextLength, sizeof(BYTE));
        tracebuf[i] = (float*)calloc(PointNumber, sizeof(float));
    }

    fseek(TraceFile, 32, SEEK_CUR);
    for (int i = 0; i < TraceNumber; i++)
    {
        for (int j = 0; j < PlaintextLength; j++)
        {
            fscanf(PlaintextFile, "%02x", &plaintextbuf[i][j]);
        }
        fread(tracebuf[i], sizeof(float), PointNumber, TraceFile);
    }


    double correlation_buf = 0.0;
    double buf[16][5] = { {0.0,}, };
    bestkey* KEY = NULL;
    KEY = (bestkey*)calloc(16, sizeof(bestkey));
    for (int point = TargetPointerlow - 1; point < TargetPointerhigh; point++)
    {
        for (int keycandidate = 0; keycandidate < 256; keycandidate++)
        {
            for (int tracenumber = 0; tracenumber < TraceNumber; tracenumber++)
            {
                for (int bytelocate = 0; bytelocate < PlaintextLength; bytelocate++)
                {
                    buf[bytelocate][0] += HM_SBox[plaintextbuf[tracenumber][bytelocate] ^ keycandidate];
                    buf[bytelocate][1] += HM_SBox[plaintextbuf[tracenumber][bytelocate] ^ keycandidate] * HM_SBox[plaintextbuf[tracenumber][bytelocate] ^ keycandidate];
                    buf[bytelocate][2] += tracebuf[tracenumber][point];
                    buf[bytelocate][3] += tracebuf[tracenumber][point] * tracebuf[tracenumber][point];
                    buf[bytelocate][4] += HM_SBox[plaintextbuf[tracenumber][bytelocate] ^ keycandidate] * tracebuf[tracenumber][point];
                }
            }
            for (int bytelocate = 0; bytelocate < PlaintextLength; bytelocate++)
            {
                if (sqrt((TraceNumber * buf[bytelocate][1] - buf[bytelocate][0] * buf[bytelocate][0]) * 
                    (TraceNumber * buf[bytelocate][3] - buf[bytelocate][2] * buf[bytelocate][2])) == 0)
                {
                    correlation_buf = 0;
                }
                else
                {
                    correlation_buf = (TraceNumber * buf[bytelocate][4] - buf[bytelocate][0] * buf[bytelocate][2]) / 
                        sqrt((TraceNumber * buf[bytelocate][1] - buf[bytelocate][0] * buf[bytelocate][0]) * 
                            (TraceNumber * buf[bytelocate][3] - buf[bytelocate][2] * buf[bytelocate][2]));
                }

                if (fabs(correlation_buf) > fabs(KEY[bytelocate].Largest_correlation))
                {
                    if (KEY[bytelocate].key != keycandidate)
                    {
                        KEY[bytelocate].Sec_largest_correlation = KEY[bytelocate].Largest_correlation;
                    }
                    KEY[bytelocate].Largest_correlation = correlation_buf;
                    KEY[bytelocate].key = keycandidate;
                    KEY[bytelocate].pointnumber = point + 1;
                    
                }
                buf[bytelocate][0] = 0;
                buf[bytelocate][1] = 0;
                buf[bytelocate][2] = 0;
                buf[bytelocate][3] = 0;
                buf[bytelocate][4] = 0;
            }
        }
        printf("%d\n", point + 1);
    }

    printf("최종 키 정보\n");
    fprintf(resultFile, "최종 키 정보\n");
    for (int i = 0; i < PlaintextLength; i++)
    {
        printf("[%d번째 바이트]\n", i + 1);
        printf("키: %02x, 해당 포인트: %d, 상관계수: %.10f, Ratio: %.10f\n", KEY[i].key, KEY[i].pointnumber, fabs(KEY[i].Largest_correlation), 
                                                                    fabs(KEY[i].Largest_correlation / KEY[i].Sec_largest_correlation));
        fprintf(resultFile, "[%d번째 바이트]\n", i + 1);
        fprintf(resultFile, "키: %02x, 해당 포인트: %d, 상관계수: %.10f, Ratio: %.10f\n", KEY[i].key, KEY[i].pointnumber, fabs(KEY[i].Largest_correlation),
                                                                                fabs(KEY[i].Largest_correlation / KEY[i].Sec_largest_correlation));
    }
    free(plaintextbuf);
    free(tracebuf);
    free(KEY);
    fclose(PlaintextFile);
    fclose(TraceFile);
    fclose(resultFile);
}

int main(){
    //tracefile_to_textfile();
    CPA();

	return 0;
}