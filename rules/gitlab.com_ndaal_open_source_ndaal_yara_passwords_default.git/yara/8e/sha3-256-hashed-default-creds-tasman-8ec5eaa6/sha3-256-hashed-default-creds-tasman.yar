rule sha3_256_hashed_default_creds_tasman
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tasman."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0f2c27ee63f493acab330e7b1baa42ebcf31ba108251e8bcf70057c9efb648d5"
    $a1="2feb0d839d212deeeb0c9b34a278aa6991bf1651714f573e5c615dfa7f43f642"
condition:
    ($a0 and $a1)
}