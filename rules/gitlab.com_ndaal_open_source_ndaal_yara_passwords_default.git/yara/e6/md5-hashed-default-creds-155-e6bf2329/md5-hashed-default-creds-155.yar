rule md5_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="97fab7cea1a10fa70c7fb1f6179de2cb"
    $a1="ad42f6697b035b7580e4fef93be20b4d"
    $a2="d9f9133fb120cd6096870bc2b496805b"
    $a3="d9f9133fb120cd6096870bc2b496805b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}