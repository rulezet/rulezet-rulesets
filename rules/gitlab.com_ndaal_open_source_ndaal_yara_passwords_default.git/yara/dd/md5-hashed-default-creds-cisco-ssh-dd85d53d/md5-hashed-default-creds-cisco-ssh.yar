rule md5_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dfeaf10390e560aea745ccba53e044ed"
    $a1="dfeaf10390e560aea745ccba53e044ed"
    $a2="dfeaf10390e560aea745ccba53e044ed"
    $a3="744b41f0dccd32ebf5d525bc1c64af5a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}