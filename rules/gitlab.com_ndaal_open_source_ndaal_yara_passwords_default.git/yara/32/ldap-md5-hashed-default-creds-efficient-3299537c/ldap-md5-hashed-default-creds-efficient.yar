rule ldap_md5_hashed_default_creds_efficient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for efficient."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a1="{MD5}1WtpmDDne6U4VWecsdJS2g=="
    $a2="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a3="{MD5}1WtpmDDne6U4VWecsdJS2g=="
    $a4="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a5="{MD5}C66i8K4gFQ23j1jN2sRCqQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}