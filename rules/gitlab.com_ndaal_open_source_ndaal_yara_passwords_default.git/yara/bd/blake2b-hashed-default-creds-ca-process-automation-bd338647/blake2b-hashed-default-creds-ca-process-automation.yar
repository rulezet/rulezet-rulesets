rule blake2b_hashed_default_creds_ca_process_automation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_process_automation."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8951a61be180c445fc4ee4216cddf3590aa1876d0d9a11337db0f6fcd988ab84b2c603bf1712418830791e0fdd80cee8bd7b97d9cbf511f334c96b0188f63b83"
    $a1="8951a61be180c445fc4ee4216cddf3590aa1876d0d9a11337db0f6fcd988ab84b2c603bf1712418830791e0fdd80cee8bd7b97d9cbf511f334c96b0188f63b83"
condition:
    ($a0 and $a1)
}