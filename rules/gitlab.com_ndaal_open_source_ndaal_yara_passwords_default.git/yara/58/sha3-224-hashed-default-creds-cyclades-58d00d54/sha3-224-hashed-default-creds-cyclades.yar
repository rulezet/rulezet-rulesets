rule sha3_224_hashed_default_creds_cyclades
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyclades."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e69a5a3471f347fd7daf6de9baf489a8ea3d7573e655d0f4d1420b24"
    $a1="1bbdd3ab361d7fd9a47de72543e337093aaa664a02248557615675c4"
    $a2="6f8b91708eab5f4d89f67e52731f56fbc2f8b14f7affc6f60c7124fd"
    $a3="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}