rule blake2b_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6e34dd9ca8281b8dd5e586660dd2c6b69c1a41d6ef44270f34827147995d46150c38347df6dfa8ba36b67094711bff0313b3bc22e6d00282e122020e691ccf8e"
    $a1="6e34dd9ca8281b8dd5e586660dd2c6b69c1a41d6ef44270f34827147995d46150c38347df6dfa8ba36b67094711bff0313b3bc22e6d00282e122020e691ccf8e"
condition:
    ($a0 and $a1)
}