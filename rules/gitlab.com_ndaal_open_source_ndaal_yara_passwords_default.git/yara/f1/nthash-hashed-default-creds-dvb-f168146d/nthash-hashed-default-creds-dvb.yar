rule nthash_hashed_default_creds_dvb
{
    meta:
        id = "dc90UszP6InxVYnQ3Mb4E"
        fingerprint = "26246410c4cc2934d595525106dd02fb213014688d1d007661e246e51b968d57"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dvb."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="02e786d95205f8c3ae45140520f454cc"
    $a1="078cff0080ddef2145ca0647366448ae"
    $a2="8792b8e83f52479c9fe127c9e311545a"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}