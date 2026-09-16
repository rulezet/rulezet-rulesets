rule sha384_hashed_default_creds_i2b2_workbench_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for i2b2_workbench_mssql."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="396a54cef63ff816cfe87d81ed558d592e65edf06688e1c953147a6924eaa5e3dcd811dce01790c66eedcca0f9c29bb9"
    $a1="e7aaac9dcee1df8433ae30ed7e73042fee1d28421010ce3c9f415fb50dcf98713b2bb9d869dc68c7ae952b921a5d712e"
    $a2="0e5865cc26cff4ac9e32b8ff5cb848435cf0797159942f20fa1c4308b6ed17f69b10d4fef1a1c3133dfe60d3c10bdfdc"
    $a3="8e80a1b738a23b5bfcaa65c5e743c6d0bdae57db8c9e2c3be53ba1a657232db1a49c636a37f78fc6ae53ce32181bd095"
    $a4="1f61fb86dfb1a3207057e4fb18e16d6849f3252b49b886d39a528b87690cc345acba5d1c09cf84fc5799fbc593dfd9dc"
    $a5="fd3767721e68e94bc6e406b01d603fc8845cb4130707fd155cb534a9c74abb72178d3975a06ffa8a636b2ac216bb9eb5"
    $a6="4b63aa0890a32d82ec8740be68b1eb40e2edc7d758807a290a808334fa2e23f745f0db9cb7ebb118e3aa0db917eeaf29"
    $a7="cd7be9b492fb318865fcef0ec44957e2e655bd16ac286f996ed4d65107c4d1d950e045e2d810e9c05bc103cadfd9ba70"
    $a8="3baff74727f4229e305f4f766fe3e6655d5afa21a3b401bc9f236ba445a9dc4c445286979b0e0eb27f348750e2a28637"
    $a9="91583deb65c535964f991bc337a01d05057ef11fc58bd3a376cd6232f42e3d362163e83c22349badc3e17e8ef74c60bf"
    $a10="b85c817fbf7950527e0cb7adcd219e3f311ac3d2a906cf0eacd2c2325f351b6350a5f712fbc9f02eaae5363e0cbf56c5"
    $a11="d09a2a98508e9bb917e525798684ca0e928c4d3fdb5151c36525839218144f209203fec5ee33d68d7c8180e6ec96ca47"
    $a12="000eb40cd9c39a01d6c2a9100183766762392be6ad2607c67e2494041d2f49ff3f32fec4125ee231ed9cd04034f2d0c2"
    $a13="d406093dcaa89c198152569fcdd34c6076f433097a284254baa3753e8fc53a6702b0a9a29bb2cdb4117acca622d9d703"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}