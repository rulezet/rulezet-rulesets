rule sha3_224_hashed_default_creds_samba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samba."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7958fb4bf861c0de89ee4fbc7e08e6a85679ea81cbd8de2181703ad"
    $a1="a7958fb4bf861c0de89ee4fbc7e08e6a85679ea81cbd8de2181703ad"
condition:
    ($a0 and $a1)
}