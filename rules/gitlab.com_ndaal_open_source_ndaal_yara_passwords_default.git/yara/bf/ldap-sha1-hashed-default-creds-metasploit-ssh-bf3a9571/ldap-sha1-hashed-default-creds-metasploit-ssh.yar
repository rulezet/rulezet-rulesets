rule ldap_sha1_hashed_default_creds_metasploit_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metasploit_ssh."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}MFiLi31OZ9yp4XAATPS/GqufmxI="
    $a1="{SHA}MFiLi31OZ9yp4XAATPS/GqufmxI="
    $a2="{SHA}oAWi0zQqaH6i0FNgyVMQesvoPgg="
    $a3="{SHA}oAWi0zQqaH6i0FNgyVMQesvoPgg="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}