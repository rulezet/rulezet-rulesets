rule mysql41_hashed_default_creds_metasploit_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metasploit_ssh."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*8D454683EA621B96CF221707C2AC8252782EAD89"
    $a1="*8D454683EA621B96CF221707C2AC8252782EAD89"
    $a2="*30EB8B252AF4B7F039B96B25259FB3411F251EF2"
    $a3="*30EB8B252AF4B7F039B96B25259FB3411F251EF2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}