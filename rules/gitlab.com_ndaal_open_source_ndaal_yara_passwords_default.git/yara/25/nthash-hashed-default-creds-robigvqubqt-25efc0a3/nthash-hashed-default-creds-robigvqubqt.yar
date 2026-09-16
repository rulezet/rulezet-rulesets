rule nthash_hashed_default_creds_robigvqubqt
{
    meta:
        id = "xLMlPgNsWNRlttjxfotsR"
        fingerprint = "3b7a40f1990505c06578728e287069ccfc26b0afa34bcaa9b0b87cf713f70fd2"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for robigvqubqt."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="07e3612b85c669f3558367fec4c46ea6"
    $a1="6753ce78fed56a4322bd54de7f3e1321"
condition:
    ($a0 and $a1)
}