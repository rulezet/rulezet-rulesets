rule blake2s_hashed_default_creds_acie_securite
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acie_securite."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="1b666c34cab923a091b1380efe105dacdeb1b4b986a0ce2391e776be2cb31fd7"
    $a2="02f9978203cf0bf2c890efb8a6fe31c265ae0127e30c5ccd04ebe21ba282c28c"
    $a3="1b666c34cab923a091b1380efe105dacdeb1b4b986a0ce2391e776be2cb31fd7"
    $a4="989c68997dddaf938c7bf176762327869db4a9f0dbaf618342adb4df26d4560a"
    $a5="1b666c34cab923a091b1380efe105dacdeb1b4b986a0ce2391e776be2cb31fd7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}