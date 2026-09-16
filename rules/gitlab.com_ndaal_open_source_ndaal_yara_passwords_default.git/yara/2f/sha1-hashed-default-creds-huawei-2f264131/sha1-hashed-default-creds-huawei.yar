rule sha1_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="3f938e8ccaabf195b24538cafcab4e76bce3bd89"
    $a2="49c5b964c0d09527f349e13eabbb56254ecccb52"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="33b35bdecbc47730ab1200d1c8439f69e77e9813"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a7="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a8="ddfdc957b3145c014c7b8561c511182a25ffbd24"
    $a9="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a10="e38fe1826b94169ddee706c80e290566e7e310f0"
    $a11="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}