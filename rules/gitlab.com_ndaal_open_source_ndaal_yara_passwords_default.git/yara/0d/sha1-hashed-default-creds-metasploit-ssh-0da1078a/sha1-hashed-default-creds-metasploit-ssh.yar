rule sha1_hashed_default_creds_metasploit_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metasploit_ssh."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="30588b8b7d4e67dca9e170004cf4bf1aab9f9b12"
    $a1="30588b8b7d4e67dca9e170004cf4bf1aab9f9b12"
    $a2="a005a2d3342a687ea2d05360c953107acbe83e08"
    $a3="a005a2d3342a687ea2d05360c953107acbe83e08"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}