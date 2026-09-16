rule sha256_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eabb754e7d250aa2709317f63f1a62165a1f76990c87454f84e176927f459f4f"
    $a1="eabb754e7d250aa2709317f63f1a62165a1f76990c87454f84e176927f459f4f"
    $a2="88269a83b8b78a92b2b67e624dc05891c00f00ac8a6c59eace99e760bde49c10"
    $a3="88269a83b8b78a92b2b67e624dc05891c00f00ac8a6c59eace99e760bde49c10"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}