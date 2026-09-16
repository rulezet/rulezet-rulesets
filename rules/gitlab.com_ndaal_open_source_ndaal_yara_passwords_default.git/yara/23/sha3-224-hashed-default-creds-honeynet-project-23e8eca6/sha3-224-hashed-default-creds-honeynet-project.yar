rule sha3_224_hashed_default_creds_honeynet_project
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeynet_project."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0452aba97190537aa9211a1911b2384fc81a7f013238c0ef118f6284"
    $a1="f827bb66e86eb5c3951b42a81455a25394dae272d6f16a72ee723220"
    $a2="0452aba97190537aa9211a1911b2384fc81a7f013238c0ef118f6284"
    $a3="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}