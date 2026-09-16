rule nthash_hashed_default_creds_metasploit_ssh
{
    meta:
        id = "1F9TUMD6kclVelTZ6q4AHB"
        fingerprint = "38881b6652a566aaf656cc999a7319560dd1074457f48af2169e5d090e354dff"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metasploit_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ccce5bc0afa4c412423937421e80de8e"
    $a1="ccce5bc0afa4c412423937421e80de8e"
    $a2="e37e07c21dbcc0c19ca053756ecc2278"
    $a3="e37e07c21dbcc0c19ca053756ecc2278"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}