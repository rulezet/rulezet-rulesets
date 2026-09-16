rule blake2s_hashed_default_creds_bewan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bewan."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="98557ecaddcb6b5724063a5044805a91e2d0c42c08d9cc36fc15e33d1b788c7a"
    $a1="98557ecaddcb6b5724063a5044805a91e2d0c42c08d9cc36fc15e33d1b788c7a"
condition:
    ($a0 and $a1)
}