rule blake2s_hashed_default_creds_hitron_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hitron_technologies."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="0294e89e49e73f06899af1236da01982ffa5e302779c9cbf1b187ad1cc52d17d"
    $a3="cb6e73929a0a9439324213614967f21610ecc62ddad6b63f4615b16d18a138d1"
    $a4="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a5="44e183ea2dab65f1b56afd25a3e6912535db21bb81e2a218b960ed0efad41f18"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}