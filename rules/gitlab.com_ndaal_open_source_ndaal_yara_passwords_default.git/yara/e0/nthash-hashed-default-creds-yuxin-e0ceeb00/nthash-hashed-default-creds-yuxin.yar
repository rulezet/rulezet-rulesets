rule nthash_hashed_default_creds_yuxin
{
    meta:
        id = "1nHf7ZDQvJUAB6vX6KrI0f"
        fingerprint = "c3e0fab7dd0daea1050f6306fe54f3638f383e67b388e50b38707bd161fb75cd"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for yuxin."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a1="0280777f37d4f4e7c478d21cec701463"
    $a2="7a70763ef136e721edf5ee6f46098367"
    $a3="0280777f37d4f4e7c478d21cec701463"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}