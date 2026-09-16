rule blake2s_hashed_default_creds_canonical_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canonical_ltd."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ff4f233a480dd8c3417c6084802708d743ff6506ea802f51cc1b8159fe8e25f0"
    $a1="ff4f233a480dd8c3417c6084802708d743ff6506ea802f51cc1b8159fe8e25f0"
condition:
    ($a0 and $a1)
}