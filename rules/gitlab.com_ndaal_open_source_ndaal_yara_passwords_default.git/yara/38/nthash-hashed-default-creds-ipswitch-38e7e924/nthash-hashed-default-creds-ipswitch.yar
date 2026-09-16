rule nthash_hashed_default_creds_ipswitch
{
    meta:
        id = "7IfBo79T2vHCSkpdpn7rHr"
        fingerprint = "9adfb46a27030b6e5b6dddcc377991e25fd40f9dd6350d134835fac4eb6427a8"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ipswitch."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="573b7e812e07337ee5d90e535f2644c5"
    $a3="16362a98f901f2bfddc325d0166db18c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}