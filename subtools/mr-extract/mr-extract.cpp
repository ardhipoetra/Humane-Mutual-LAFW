#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

/* SGXSDKのフォルダパスはここで指定。自身の環境に合わせて変更する */
std::string sdk_path = "/opt/intel/sgxsdk/";

/* 署名済みEnclaveイメージファイル名はここで指定。
 * 自身の環境に合わせて変更する */
std::string image_path = "../../";


int main()
{
    std::string input_type;
    std::cout << "Input 0 or 1 (0: responder, 1: initiator):" << std::endl;
    std::cin >> input_type;

    /* グローバル変数にイメージ名を追記 */
    if(input_type == "0") image_path += "responder_enclave.signed.so";
    else if(input_type == "1") image_path += "initiator_enclave.signed.so";
    else abort();

    std::string signing_tool_path = sdk_path + std::string("bin/x64/sgx_sign");
    
    pid_t pid;
    int status;

    pid = fork();

    if(pid == -1)
    {
        std::cerr << "Failed to fork process for sgx_sign." << std::endl;
        exit(1);
    }
    else if(pid == 0)
    {
        char *cmd[] = {
            (char*)"sgx_sign",
            (char*)"dump",
            (char*)"-enclave",
            (char*)image_path.c_str(),
            (char*)"-dumpfile",
            (char*)"tmp.txt",
            NULL
        };

        std::cout << "-------- message from sgx_sign tool --------" << std::endl;
        execv(signing_tool_path.c_str(), cmd);

        std::cerr << "Failed to exec sgx_sign." << std::endl;
        exit(1);
    }

    waitpid(pid, &status, 0);
    std::cout << "--------------------------------------------" << std::endl;

    if(!WIFEXITED(status))
    {
        std::cerr << "Failed to exit sgx_sign successfully." << std::endl;
        exit(1); 
    }

    /* ここまで来ればsgx_signの実行は正常に完了している */
    std::ifstream ifs("tmp.txt");

    if(!ifs)
    {
        std::cerr << "Failed to open dump file." << std::endl;
        exit(1);
    }

    std::string line;
    std::string mrenclave, mrsigner;

    while(getline(ifs, line))
    {
        if(line.find("enclave_css.body.enclave_hash.m") != std::string::npos)
        {
            /* MRENCLAVE値を示す2行を読み取る */
            getline(ifs, line);
            mrenclave += line;
            getline(ifs, line);
            mrenclave += line;
        }
        else if(line.find("mrsigner->value") != std::string::npos)
        {
            /* MRSIGNER値を示す2行を読み取る */
            getline(ifs, line);
            mrsigner += line;
            getline(ifs, line);
            mrsigner += line;
        }
    }

    //std::cout << mrenclave << std::endl;
    //std::cout << mrsigner << std::endl;

    ifs.close();

    if(0 != std::remove("tmp.txt"))
    {
        std::cerr << "Failed to delete temporary dump file." << std::endl;
        return 1;
    }

    /* 連続的なHexバイト列に変換 */
    std::stringstream mre_ss, mrs_ss;
    std::string byte_hex;

    mre_ss << mrenclave;

    std::cout << "\nCopy and paste following measurement values into enclave code." << std::endl;
    std::cout << "\033[32mMRENCLAVE value -> \033[m\n";

    std::string mre_result, mre_kss, mrs_result;

    int count = 0;

    while(getline(mre_ss, byte_hex, ' '))
    {
        mre_result += byte_hex;
        mre_result += ", ";
        mre_kss += byte_hex.substr(2, 3);

        if(count > 0 && (count + 1) % 8 == 0)
        {
            mre_result += "\n";
            mre_kss += "\n";
        }

        count++;
    }

    mre_result.pop_back();
    mre_result.pop_back();
    mre_result.pop_back();
    std::cout << mre_result << std::endl;

    std::cout << "\n\033[32mMRENCLAVE value for kss -> \033[m\n";

    mre_kss.pop_back();
    std::string::size_type start = 0;
    std::string::size_type end;

    end = mre_kss.find('\n', start);
    std::cout << "<ISVFAMILYID_H>0x" << mre_kss.substr(start, end - start) << "</ISVFAMILYID_H>" << std::endl;
    start = end + 1;

    // Line 2
    end = mre_kss.find('\n', start);
    std::cout << "<ISVFAMILYID_L>0x" << mre_kss.substr(start, end - start) << "</ISVFAMILYID_L>" << std::endl;
    start = end + 1;

    // Line 3
    end = mre_kss.find('\n', start);
    std::cout << "<ISVEXTPRODID_H>0x" << mre_kss.substr(start, end - start) << "</ISVEXTPRODID_H>" << std::endl;
    start = end + 1;

    std::cout << "<ISVEXTPRODID_L>0x" << mre_kss.substr(start) << "</ISVEXTPRODID_L>" << std::endl;
    // Line 4

    std::cout << "\n\033[32mMRSIGNER value  -> \033[m\n";

    mrs_ss << mrsigner;
    count = 0;

    while(getline(mrs_ss, byte_hex, ' '))
    {
        mrs_result += byte_hex;
        mrs_result += ", ";

        if(count > 0 && (count + 1) % 8 == 0) mrs_result += "\n";

        count++;
    }

    mrs_result.pop_back();
    mrs_result.pop_back();
    mrs_result.pop_back();
    std::cout << mrs_result << std::endl;

    std::cout << "\n" << std::endl;

    return 0;
}
