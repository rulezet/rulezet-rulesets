rule ldap_md5_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}QgclI4yfr2nW3WDpUfZ/YA=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}QgclI4yfr2nW3WDpUfZ/YA=="
    $a3="{MD5}C66i8K4gFQ23j1jN2sRCqQ=="
    $a4="{MD5}6LhLnSFZzMto/xj7SZWnPA=="
    $a5="{MD5}wnOhhnmuZusuw877tSnZ0w=="
    $a6="{MD5}6LhLnSFZzMto/xj7SZWnPA=="
    $a7="{MD5}EdoqKmEmtLD9INIU/q8R8Q=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}