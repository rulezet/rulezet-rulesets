rule blake2s_hashed_default_creds_metasploit_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metasploit_ssh."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e3753142fddf2d0205385bb5ce095d7a9965047701ab02115eaf8d4b970ee50f"
    $a1="e3753142fddf2d0205385bb5ce095d7a9965047701ab02115eaf8d4b970ee50f"
    $a2="90a0c24c1c32d0e35062d7f58c7a61e9d4ff21bc7f83b8a5fb4f690aa584b1ff"
    $a3="90a0c24c1c32d0e35062d7f58c7a61e9d4ff21bc7f83b8a5fb4f690aa584b1ff"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}