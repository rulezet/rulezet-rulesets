rule sha224_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="05f4a1daf9a07ebaac0967a6d191537ca0d414a3d863ce3734a792bb"
    $a1="18250460059f5cf002f219bdf70d720b8d7eaa2f250a8aaa56dadea9"
condition:
    ($a0 and $a1)
}