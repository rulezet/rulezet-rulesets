rule sha1_hashed_default_creds_adobe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adobe."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="f64cd8e32f5ac7553c150bd05d6f2252bb73f68d"
    $a3="f64cd8e32f5ac7553c150bd05d6f2252bb73f68d"
    $a4="0a92fab3230134cca6eadd9898325b9b2ae67998"
    $a5="0a92fab3230134cca6eadd9898325b9b2ae67998"
    $a6="07b94dce1c5fc71e0b62e5a34010e60fe9e50300"
    $a7="5d672ecca683475ad849b35781f8e216b74088cb"
    $a8="d35514736146439b7277437016cdb40d7fb65497"
    $a9="b10c316984dd14ef10108251e407840ead6de443"
    $a10="b05753f2d4fd4746e78a07788a0fc3ff48e8f35e"
    $a11="b05753f2d4fd4746e78a07788a0fc3ff48e8f35e"
    $a12="aa198c6806811aa31b6f07a581b851420af6a0e8"
    $a13="aa198c6806811aa31b6f07a581b851420af6a0e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}