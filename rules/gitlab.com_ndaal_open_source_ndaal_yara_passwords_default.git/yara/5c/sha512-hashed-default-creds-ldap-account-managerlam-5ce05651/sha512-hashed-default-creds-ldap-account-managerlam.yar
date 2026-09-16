rule sha512_hashed_default_creds_ldap_account_managerlam
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ldap_account_managerlam."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3e259fd13956f0821b5d08dd6f15b42f21f5513f74a7118139a4e06d9708511652735ad1dd834b9228c6063247bae86d85044d5e92f7a88d5ac0dbba5cdfa76f"
    $a1="3e259fd13956f0821b5d08dd6f15b42f21f5513f74a7118139a4e06d9708511652735ad1dd834b9228c6063247bae86d85044d5e92f7a88d5ac0dbba5cdfa76f"
condition:
    ($a0 and $a1)
}