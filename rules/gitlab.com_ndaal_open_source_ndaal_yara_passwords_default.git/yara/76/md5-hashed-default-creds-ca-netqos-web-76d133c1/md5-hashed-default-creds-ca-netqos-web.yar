rule md5_hashed_default_creds_ca_netqos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_netqos_web."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0cbe44e34ea1eaf8ee7aad7f7f60e337"
    $a1="553188acbaedf9e84d3e2802c399720a"
    $a2="0cbe44e34ea1eaf8ee7aad7f7f60e337"
    $a3="8b51cbc36aa0daf9cb1305c3e7b149d8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}