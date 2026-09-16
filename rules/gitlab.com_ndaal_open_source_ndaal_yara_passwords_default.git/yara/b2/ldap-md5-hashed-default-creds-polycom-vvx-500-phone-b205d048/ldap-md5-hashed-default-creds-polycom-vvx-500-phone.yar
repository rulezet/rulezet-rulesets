rule ldap_md5_hashed_default_creds_polycom_vvx_500_phone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom_vvx_500_phone."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}JQz4tRx3Pz+NyLS+hnqaAg=="
    $a1="{MD5}46/tAEewgFnQ+toQ9ADB5Q=="
    $a2="{MD5}ICy5YqxZB1uWSwcVLSNLcA=="
    $a3="{MD5}j5v+nRNFI3yzsrIFhk2gdQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}