rule mysql41_hashed_default_creds_symmetricom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symmetricom."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*43F90B45703A27C42A93197C4AE1867A67751322"
    $a1="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a2="*F45015A7DF906A88E089105F69A2891DF708975B"
    $a3="*60CE05C60319F4878B7A51EDF3DC98089E0C6E26"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}