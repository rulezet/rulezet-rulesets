rule md5_hashed_default_creds_data_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for data_general."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4b583376b2767b923c3e1da60d10de59"
    $a1="4b583376b2767b923c3e1da60d10de59"
    $a2="11d8c28a64490a987612f2332502467f"
    $a3="11d8c28a64490a987612f2332502467f"
    $a4="4b583376b2767b923c3e1da60d10de59"
    $a5="11d8c28a64490a987612f2332502467f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}