rule nthash_hashed_default_creds_netapp
{
    meta:
        id = "3tHxtHoVi8jVEjd5LfwdYl"
        fingerprint = "f54853ca920aff5dfc08ce1e8210011072e5712f0e91714b2877384e89a3c306"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netapp."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="df5ee178915cb667239ec9496166247e"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="3008c87294511142799dca1191e69a0f"
    $a3="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}