rule sha384_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="daead2f5d798969185c0b94acb330300f835db65a2d91cd4095104d96b469515fce7ab29373dc30cc9ca851059e33e4f"
    $a1="daead2f5d798969185c0b94acb330300f835db65a2d91cd4095104d96b469515fce7ab29373dc30cc9ca851059e33e4f"
    $a2="3d7c953602338bb1e6a178791c0f9aad85184e41481c5dbcc36687ac3b1b946d9a87e9b247309bcbe76c825871a551cd"
    $a3="3d7c953602338bb1e6a178791c0f9aad85184e41481c5dbcc36687ac3b1b946d9a87e9b247309bcbe76c825871a551cd"
    $a4="c901c28c86086170664e7f141cee6c27274093935d179003f14dc73f282f96da5ed0ad5609c68d035a12ea2f7ebb1b68"
    $a5="c901c28c86086170664e7f141cee6c27274093935d179003f14dc73f282f96da5ed0ad5609c68d035a12ea2f7ebb1b68"
    $a6="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a7="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a8="eaa2adcd989acbb07569f45d3175b6c04619ffcedb57b01d741b171364c530f76972a0fc915f1a6929833a6f55df2015"
    $a9="fba4a3defbe0652995f93f9d8be36443b67d1d959f31f6c9cfcb95f75efd14a0a0f2e67651ec90a3adb7ee7e47aa7c9d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}