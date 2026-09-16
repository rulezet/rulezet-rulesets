rule blake2b_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a17b959819af7afcb478a1962965f59ac90a464ac075a72ffdebc63c97b46f2193b9b6efc5dd7e5a19e08a3987292dd221479578ea6272695a84c31fd2fd032"
    $a1="89b83c415aca676c403c3214115b1a42e181c09d9373e4344bc13a48b253c1bd46b44de36b156eccfa4fc992794fe6820e10f027f4808dfc190e06ef13097cc1"
condition:
    ($a0 and $a1)
}