rule ldap_md5_hashed_default_creds_sierra_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sierra_wireless."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}gnzLDuqKcGxMNKFokfhOew=="
    $a1="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a2="{MD5}gnzLDuqKcGxMNKFokfhOew=="
    $a3="{MD5}pBorKCFGVSjgE2Hbw2OxSw=="
    $a4="{MD5}gnzLDuqKcGxMNKFokfhOew=="
    $a5="{MD5}SyoVKYZ7jWl2hbFyLM0BSQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}