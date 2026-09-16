rule nthash_hashed_default_creds_modernie_ssh
{
    meta:
        id = "sfdHr1PxqCKKjRI0GjcA9"
        fingerprint = "b9dcab3416b76fd649fd9978c3b16ab3a68191ba2238ec268970c6efbe3d0c1c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d0a16cfc061c3359db455d00ec27035"
    $a1="db6befd63bd20f737df246520c36fb8b"
condition:
    ($a0 and $a1)
}