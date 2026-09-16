rule sha3_256_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f23c40ac856200d8b3b266d94b57e0bbfa752a6366363a5694dd11ba22b901b2"
    $a1="b41a9cc43c03074072ced4fade423c375ca7d953b4c5248065bb89f73640e628"
condition:
    ($a0 and $a1)
}