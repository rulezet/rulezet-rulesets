rule mysql323_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="67d7ee501cc18bcc"
    $a1="43e9a4ab75570f5b"
    $a2="2b50114e7dd56ee6"
    $a3="67457e226a1a15bd"
    $a4="728889ee26187486"
    $a5="1e0c530062ec7e17"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}