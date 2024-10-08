# Humane Intel SGX Local Attestation Framework (Humane-LAFW)

This has been machine-translated by deepl. Original README is available on [here](https://github.com/acompany-develop/Humane-LAFW/blob/main/README.md)


## Abstract
This repository contains the code for the LA Framework (LAFW), a framework that enables Local Attestation (LA) in Intel SGX to be easily implemented in-process with a “humane” level of difficulty.

Compared to the code included in the official SGX SDK, the code is completed within a process rather than between processes, and the minimum necessary processing is implemented with explanatory comments, making it easier to understand and use for a variety of people.

In Humane-LAFW, an application (App) outside the Enclave acts as an intermediary between the Proving Enclave (Initiator), which proves its own identity, and the Verifying Enclave (Responder), which verifies the Proving Enclave. LA proceeds in the form of a mediation between the Initiator, the proving party, and the Responder, the verifying party.

## Introduction
### System Requirements
* OS: Ubuntu 22.04.3 LTS
* SGXSDK: Version 2.21

### SGX Environment Setup
Clone Linux-SGX and install SGXSDK and SGXPSW according to the README.

If you are using Linux kernel 5.11 or later, you do not need to install SGX driver by yourself because it is built in by default (in-kernel driver).

If you are using a Linux kernel less than 5.11,

* linux-sgx-driver
* linux-sgx-dcap driver

if you are using a Linux kernel lower than 5.11.

### Deployment of Humane-LAFW
Clone this repository in any directory.

## Preparation
### Enclave Signing Key Settings
The keys used to sign Enclave are stored by default as `Initiator_Enclave/private_key.pem` and `Responder_Enclave/private_key.pem`.

However, since it is preferable to use keys generated by the user in actual operation, please create new keys for both Enclaves separately using the following commands and store

```
openssl genrsa -out private_key.pem -3 3072
```

### Preparation of Identity Information on the Proving Side
In LA, the MRENCLAVE and MRSIGNER of the proof side Enclave are hard-coded into the verification side Enclave and used for identity verification, so it is necessary to build the Enclave once and extract the MRENCLAVE and other information from it.  

In addition, since the verification side can also verify the identity of the verification side as far as MRSIGNER is concerned, it is also possible to output the identity information about the verification side Enclave.

The following procedure is used to extract these two values and perform hard coding.

* Execute the following command in the root directory of the repository to build the various applications and Enclave.
  ```
  make
  ```

* Go to the directory where `mr-extract`, an auxiliary tool for extracting identity information, is located.
  ```
  cd subtools/mr-extract
  ```
* If the SGXSDK or signed Enclave image name is not as shown below, open `mr-extract.cpp` and edit the following parts as appropriate.

  ``` cpp
  /* SGXSDK folder path is specified here. Change it according to your own environment */
  std::string sdk_path = "/opt/intel/sgxsdk/";

  /* Specify here the name of the signed Enclave image file.
  * Change it to suit your own environment */
  std::string image_path = "../../enclave.signed.so";
  ```

* Build with the `make` command.
  ```
  make
  ```

* Execute the executable file generated by the build.
  ```
  ./mr-extract
  ```

* The following standard output is displayed. Enter 0 to display the identity information of the verifying Enclave or 1 to display that of the proving Enclave, and press Enter.
  ```
  Input 0 or 1 (0: responder, 1: initiator):
  ```

* The following standard output is then displayed
  ```
  -------- message from sgx_sign tool --------
  Succeed.
  --------------------------------------------

  Copy and paste following measurement values into enclave code.
  MRENCLAVE value -> 
  0x6c, 0xea, 0x2a, 0xf0, 0x97, 0x51, 0x62, 0x02, 
  0xa3, 0xb1, 0xfd, 0x59, 0x49, 0x4a, 0x29, 0x91, 
  0x14, 0x81, 0xea, 0x55, 0x32, 0x77, 0x6a, 0x91, 
  0x09, 0x06, 0xe7, 0x67, 0x28, 0x2e, 0x93, 0x0d

  MRSIGNER value  -> 
  0x4a, 0x94, 0xff, 0x27, 0x69, 0x36, 0x2a, 0xe6, 
  0x25, 0xc9, 0x0b, 0x38, 0x1f, 0x5a, 0xdb, 0xac, 
  0x03, 0x23, 0xa3, 0xb2, 0x47, 0x96, 0x65, 0x84, 
  0x36, 0xdc, 0x45, 0x89, 0xcd, 0xb4, 0x19, 0x19
  ```

* If the identity information of the verifying Enclave is output, the `Initiator_Enclave/initiator_enclave.cpp`.
  ```cpp
  /* Responder's MRENCLAVE does not verify due to LA's unidirectional nature */
  sgx_measurement_t mr_signer = {
      0xfd, 0x9c, 0x50, 0x01, 0x42, 0x64, 0x13, 0x9a, 
      0x83, 0x01, 0xab, 0x5d, 0x9e, 0x78, 0x4e, 0x7d, 
      0x97, 0xa8, 0x64, 0x73, 0x33, 0x64, 0x4e, 0x81, 
      0x2a, 0x36, 0x11, 0x6f, 0x87, 0xd5, 0xcc, 0x99
  };
  ```
  Hard-code the `MRSIGNER value ->` section by overwriting the four lines of the `MRSIGNER value ->` section in the `MRSIGNER value ->` section.  
  If you want the identity information of the proving side Enclave to be output, you can use the following line in `Responder_Enclave/responder_enclave.cpp`.
  ```cpp
  sgx_measurement_t mr_enclave = {
      0x7f, 0x64, 0x6d, 0x31, 0x88, 0x96, 0x9d, 0xab, 
      0xd2, 0x50, 0xd1, 0xb4, 0xfe, 0x8b, 0x0e, 0x11, 
      0x94, 0x29, 0x40, 0xe9, 0xb1, 0xe0, 0xfc, 0xbd, 
      0xf4, 0xf0, 0x5d, 0xa2, 0x29, 0x57, 0x38, 0xa8
  };

  sgx_measurement_t mr_signer = {
      0x4a, 0x94, 0xff, 0x27, 0x69, 0x36, 0x2a, 0xe6, 
      0x25, 0xc9, 0x0b, 0x38, 0x1f, 0x5a, 0xdb, 0xac, 
      0x03, 0x23, 0xa3, 0xb2, 0x47, 0x96, 0x65, 0x84, 
      0x36, 0xdc, 0x45, 0x89, 0xcd, 0xb4, 0x19, 0x19
  };
  ```
  Hard code the `MRENCLAVE value ->` and `MRSIGNER value ->` parts by overwriting 4 lines each in the `MRENCLAVE value ->` and `MRSIGNER value ->` parts.

* Return to the repository root directory and build the application and Enclave again.
  ```
  make
  ```

## Execution
Once the build and configuration is complete, run the executable binary with the following command to execute LA

```
./app
```

Afterwards, LA is executed, and if the identity verification in LA is successful, a secure cryptographic communication channel is established between the two Enclaves using the session common key obtained from the elliptic curve Diffie-Hellman key sharing that was performed in parallel to LA.

A simple sample secret computation is then performed, where the verifier securely sends two integers of the sample in the verifying Enclave to the proving Enclave as secret information, the verifier decrypts them and calculates the average of the two values, and the resulting average value is output standard in OCALL.