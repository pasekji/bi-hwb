#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <bitset>
#include <vector>

#define TRNG_PAIR_CNT   64

int main()
{
    std::string tracelen_s;
    std::string fs_s;
    int tracelen;
    int fs;
    std::string trng_val;
    std::fstream f;
    f.open("data_info.txt");
    std::getline(f, tracelen_s);
    std::getline(f, fs_s);
    std::getline(f, trng_val);
    std::stringstream s1;
    std::stringstream s2;
    s1 << tracelen_s;
    s1 >> tracelen;
    s2 << fs_s;
    s2 >> fs;
    /*
    std::cout << tracelen << std::endl;
    std::cout << fs << std::endl;
    std::cout << trng_val << std::endl;
    */

    std::ifstream inputFile("data.bin");
    std::vector<uint8_t> traces_v;
    if(inputFile)
    {
        uint8_t value;
        while(inputFile >> value)
        {
            traces_v.push_back(value);
        }
    }
    /*
    std::cout << traces_v.size() << std::endl;
    std::cout << (traces_v.size()/tracelen) << std::endl;
    std::cout << tracelen << std::endl;
    */
    std::vector<std::vector<uint8_t>> traces((traces_v.size()/tracelen), std::vector<uint8_t>(tracelen));

    int iterator = 0;
    for(int i = 0; i < (traces_v.size()/tracelen); i++)
    {
        for(int j = 0; j < tracelen; j++)
        {
            traces[i][j] = traces_v[iterator];
            iterator++;
        }
    }

    std::vector<std::vector<bool>> traces_bin((traces_v.size()/tracelen), std::vector<bool>(tracelen));

    for(int i = 0; i < (traces_v.size()/tracelen); i++)
    {
        for(int j = 0; j < tracelen; j++)
        {
            if(traces[i][j] >= 128)
            {
                traces_bin[i][j] = true;
            }
            else
                traces_bin[i][j] = false;
        }
    }

    std::vector<std::vector<bool>> rising_edges((traces_v.size()/tracelen), std::vector<bool>(tracelen));
    for(int i = 0; i < (traces_v.size()/tracelen); i++)
    {
        for(int j = 0; j < tracelen; j++)
        {
            if(traces_bin[i][j] == false)
            {
                if((j+1) <= tracelen)
                {
                    if(traces_bin[i][j+1] == true)
                    {
                        rising_edges[i][j] = true;
                    }
                    else
                    {
                        rising_edges[i][j] = false;
                    }
                }
                else
                {
                    rising_edges[i][j] = false;
                }
            }
            else
            {
                rising_edges[i][j] = false;
            }
        }
    }

    std::vector<int> cnt;
    //std::cout << rising_edges.size() << std::endl;

    for(int i = 0; i < (traces_v.size()/tracelen); i++)
    {
        int value = 0;
        for(int j = 0; j < tracelen; j++)
        {
            if(rising_edges[i][j] == true)
                value++;
        }
        cnt.push_back(value);
    }

    /*
    std::cout << cnt.size() << std::endl;
    for(int i = 0; i < 128; i++)
        std::cout << cnt[i] << std::endl;
    */

    std::vector<std::vector<int>> cnt_pair(TRNG_PAIR_CNT, std::vector<int>(2));

    iterator=0;
    for(int i = 0; i < TRNG_PAIR_CNT; i++)
    {
        for(int j = 0; j < 2; j++)
        {
            cnt_pair[i][j] = cnt[iterator];
            iterator++;
        }
    }

    /*
    for(int i = 0; i < TRNG_PAIR_CNT; i++)
    {
        for(int j = 0; j < 2; j++)
        {
            std::cout << cnt_pair[i][j] << "     ";
        }
        std::cout << std::endl;
    }
    */

    std::vector<int> cnt_smaller;
    for(int i = 0; i < TRNG_PAIR_CNT; i++)
    {
        if(cnt_pair[i][0] <= cnt_pair[i][1])
            cnt_smaller.push_back(cnt_pair[i][0]);
        else
            cnt_smaller.push_back(cnt_pair[i][1]);
    }

    //std::cout << cnt_smaller.size() << std::endl;
    
    std::vector<int> cnt_sel;
    for(int i = 0; i < 64; i++)
    {
        cnt_sel.push_back(cnt_smaller[i] & 0b11);
    }
    /*
    std::cout << cnt_sel.size() << std::endl;
    for(int i = 0; i < 64; i++)
        std::cout << cnt_sel[i] << std::endl;
    */
    std::stringstream s3;
    for(int i = 0; i < 64; i++)
    {
        //std::cout << std::bitset<2>(cnt_sel[i]) << std::endl;
        s3 << std::bitset<2>(cnt_sel[i]);
    }
    std::string estimate;
    s3 >> estimate;
    //std::cout << estimate.length() << std::endl;
    std::bitset<128> final(estimate);
    std::cout << "computed value in binary: " << std::endl << final.to_string() << std::endl;

    // trng_val to bin from https://www.rapidtables.com/convert/number/hex-to-binary.html
    std::string ref_value = "1010101110111111000100101111110000011100110101001000000101110011110010001001000000010011101110101011100000110001100101001000000";
    std::cout << std::endl;
    std::cout << "reference value in binary: " << std::endl << "0" << ref_value << std::endl;
    std::string ref_value1 = "0" + ref_value;

    int res = ref_value1.compare(final.to_string());
    std::cout << std::endl;

    if (res == 0)
        std::cout << "computed value and reference value match!" << std::endl;
    else
        std::cout << "computed value and reference value are different!" << std::endl;


}