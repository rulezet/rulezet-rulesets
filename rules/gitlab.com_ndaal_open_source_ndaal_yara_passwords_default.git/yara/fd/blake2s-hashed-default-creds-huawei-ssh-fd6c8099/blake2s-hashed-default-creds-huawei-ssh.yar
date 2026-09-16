rule blake2s_hashed_default_creds_huawei_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei_ssh."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a4="bbb4fe984d23a35edea1c68c6cbb56c7ec8bd2e34a82a04951ac8e4b62bb5609"
    $a5="bbb4fe984d23a35edea1c68c6cbb56c7ec8bd2e34a82a04951ac8e4b62bb5609"
    $a6="ecf90201f780a7e31410e79720125d4f0e7732f021614a51abc2dc9d68e277ab"
    $a7="61192aff78cb38a71858a3a9adf0deda1aa3bc771dde2ebad68bf1183b95daef"
    $a8="98c7eb8f78c0b8786e16cb50f57ad7230d9316dfed040a70c4dff0d97b426fc6"
    $a9="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a10="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a11="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a12="80688a4089ed8ece69d6710dfadd097f1decae2248cb4b6ab9b73b1206b0c820"
    $a13="80688a4089ed8ece69d6710dfadd097f1decae2248cb4b6ab9b73b1206b0c820"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}