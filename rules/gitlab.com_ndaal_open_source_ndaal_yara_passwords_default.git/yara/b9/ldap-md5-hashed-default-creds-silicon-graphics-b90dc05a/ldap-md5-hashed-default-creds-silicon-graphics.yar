rule ldap_md5_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}aTG3NdaPyOmqsLFUfcD+JA=="
    $a1="{MD5}aTG3NdaPyOmqsLFUfcD+JA=="
    $a2="{MD5}BuPTb6MM6glVRROYVK0fuQ=="
    $a3="{MD5}BuPTb6MM6glVRROYVK0fuQ=="
    $a4="{MD5}8KQCWztJs+JWAEUD7jHfjA=="
    $a5="{MD5}8KQCWztJs+JWAEUD7jHfjA=="
    $a6="{MD5}H29CM04XCaTg+ZIq14mRKw=="
    $a7="{MD5}H29CM04XCaTg+ZIq14mRKw=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}