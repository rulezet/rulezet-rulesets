rule sha3_384_hashed_default_creds_tim_schaab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tim_schaab."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6298254a634a568a9aa432814c5563e3ae408330cfa0370fca364cc36ccbd6b0d96cf4ae41179a3526fc4e099651a024"
    $a1="959a5b5f7865fce20f855926b93cce02afa1a00369cb293f8fdce3f3a8fc978336dbd1b31f5407ca50da05936af042d6"
condition:
    ($a0 and $a1)
}