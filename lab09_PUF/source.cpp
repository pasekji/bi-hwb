#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <bitset>


using namespace std;

typedef struct
{
	uint8_t bytes[512];
} PUF_ANWSER;

typedef struct
{
	PUF_ANWSER fileStruct[1000];
} FILE_STRUCT;

const int length = 4096;

PUF_ANWSER refAnw[10];
int hm[1000];
int refs[10][4096];

int hammingDistIntra(uint8_t x[512], int p)
{
    int count = 0;
    for(int i = 0; i < 512; i++)
    {
        string a = bitset<8>(x[i]).to_string();
        string b = bitset<8>(refAnw[p].bytes[i]).to_string();
        for(int j = 0; j < 8; j++)
        {
            if(a[j] != b[j])
                count++;
        }
    }
    return count;
}

int hammingDistInter(int x, int y)
{
    int count = 0;
    for(int i = 0; i < 512; i++)
    {
        string a = bitset<8>(refAnw[x].bytes[i]).to_string();
        string b = bitset<8>(refAnw[y].bytes[i]).to_string();
        for(int j = 0; j < 8; j++)
        {
            if(a[j] != b[j])
                count++;
        }
    }
    return count;
}

// opravit na hledani majority na urovni jednotlivych bitu 
/*
void comupteAverage(FILE_STRUCT chip, int p)
{
    for(int j = 0; j < 512; j++)
    {
        uint8_t tmp[1000];
        for(int i = 0; i < 1000; i++)
        {
            tmp[i] = chip.fileStruct[i].bytes[j];
        }
        uint8_t avg = 0;
        for(int k = 0; k < 1000; k++)
            avg += (tmp[k] - avg) / (k + 1);
        refAnw[p].bytes[j] = avg;
    }
}
*/

void buildBack(int p)
{
    uint8_t avg = 0;
    for(int i = 1; i <= 512; i++)
    {
        avg = (128 * (refs[p][(8*i)-1])) + (64 * (refs[p][(7*i)-1])) + (32 * (refs[p][(6*i)-1])) + (16 * (refs[p][(5*i)-1])) + (8 * (refs[p][(4*i)-1])) + (4 * (refs[p][(3*i)-1])) + (2 * (refs[p][(2*i)-1])) + (1 * (refs[p][(1*i)-1]));
        refAnw[p].bytes[i-1] = avg;
    }
}

void comupteMajorBits(FILE_STRUCT chip, int p)
{
    uint8_t one = 255;
    string ones = bitset<8>(one).to_string();
    int pos = 0;
    for(int j = 0; j < 512; j++)
    {
        uint8_t tmp[1000];
        for(int i = 0; i < 1000; i++)
        {
            tmp[i] = chip.fileStruct[i].bytes[j];
        }
        int bits[8];
        for(int k = 0; k < 1000; k++)
        {
            string a = bitset<8>(tmp[k]).to_string();
            for(int h = 0; h < 8; h++)
            {
                if(a[h] == ones[0])
                    bits[h]++;
            }
        }
        for(int h = 0; h < 8; h++)
        {
            if(bits[h] >= 500)
                refs[p][pos] = 1;
            else
                refs[p][pos] = 0;
            pos++;
        }
    }
    buildBack(p);
}

double HDintra(FILE_STRUCT chip, int p)
{
    comupteMajorBits(chip, p);

    for(int i = 0; i < 1000; i++)
        hm[i] = hammingDistIntra(chip.fileStruct[i].bytes, p);

    double count = 0;
    for(int i = 0; i < 1000; i++)
    {
        double tmp = (double)hm[i] / (double)4096;
        count += tmp;
    }

    double final = count / (double)1000;
    final = final * (double)100;
    return final;
}

double HDinter(int N)
{
    double count = 0; 
    for(int i = 0; i < (N-1); i++)
    {
        for(int j = i + 1; j < N; j++)
        {
            double tmp = (double)hammingDistInter(i, j) / (double)4096;
            count += tmp;
        }
    }

    double final = (double)( ((double)2) / ((double)N * ((double)N-(double)1)) ) * count;
    final = final * (double)100;
    return final;
}

int main()
{
    FILE_STRUCT chip[10];
    FILE * fh1 = fopen("chip1.bin","r");
    FILE * fh2 = fopen("chip2.bin","r");
    FILE * fh3 = fopen("chip3.bin","r");
    FILE * fh4 = fopen("chip4.bin","r");
    FILE * fh5 = fopen("chip5.bin","r");
    FILE * fh6 = fopen("chip6.bin","r");
    FILE * fh7 = fopen("chip7.bin","r");
    FILE * fh8 = fopen("chip8.bin","r");
    FILE * fh9 = fopen("chip9.bin","r");
    FILE * fh10 = fopen("chip10.bin","r");

    if(!fh1 || !fh2 || !fh3 || !fh4 || !fh5 || !fh6 || !fh7 || !fh8 || !fh9 || !fh10)
    {
        cout << "error opening input file" << endl;
        exit(1);
    }

    int res = fread((char*)&chip[0], sizeof(PUF_ANWSER), 1000, fh1);
    if (res != 1000)
    {
        fputs("error reading data chip1.bin",stderr); 
        exit(3);
    }

    res = fread((char*)&chip[1], sizeof(PUF_ANWSER), 1000, fh2);
    if (res != 1000)
    {
        fputs("error reading data chip2.bin",stderr); 
        exit(3);
    }
    
    res = fread((char*)&chip[2], sizeof(PUF_ANWSER), 1000, fh3);
    if (res != 1000)
    {
        fputs("error reading data chip3.bin",stderr); 
        exit(3);
    }

    res = fread((char*)&chip[3], sizeof(PUF_ANWSER), 1000, fh4);
    if (res != 1000)
    {
        fputs("error reading data chip4.bin",stderr); 
        exit(3);
    }

    res = fread((char*)&chip[4], sizeof(PUF_ANWSER), 1000, fh5);
    if (res != 1000)
    {
        fputs("error reading data chip5.bin",stderr); 
        exit(3);
    }

    res = fread((char*)&chip[5], sizeof(PUF_ANWSER), 1000, fh6);
    if (res != 1000)
    {
        fputs("error reading data chip6.bin",stderr); 
        exit(3);
    }

    res = fread((char*)&chip[6], sizeof(PUF_ANWSER), 1000, fh7);
    if (res != 1000)
    {
        fputs("error reading data chip7.bin",stderr); 
        exit(3);
    }

    res = fread((char*)&chip[7], sizeof(PUF_ANWSER), 1000, fh8);
    if (res != 1000)
    {
        fputs("error reading data chip8.bin",stderr); 
        exit(3);
    }

    res = fread((char*)&chip[8], sizeof(PUF_ANWSER), 1000, fh9);
    if (res != 1000)
    {
        fputs("error reading data chip9.bin",stderr); 
        exit(3);
    }

    res = fread((char*)&chip[9], sizeof(PUF_ANWSER), 1000, fh10);
    if (res != 1000)
    {
        fputs("error reading data chip10.bin",stderr); 
        exit(3);
    }

    for(int i = 0; i < 10; i++)
    {
        double res = HDintra(chip[i], i);
        cout << "chip" << (i+1) << " HDintra: " << res << "%" << endl;
    }

    double inter = HDinter(10);
    cout << "========================" << endl;
    cout << "chip" << " HDinter: " << inter << "%" << endl;

    fclose(fh1);
    fclose(fh2);
    fclose(fh3);
    fclose(fh4);
    fclose(fh5);
    fclose(fh6);
    fclose(fh7);
    fclose(fh8);
    fclose(fh9);
    fclose(fh10);
    return 0;
}