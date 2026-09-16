rule nthash_hashed_default_creds_wyse
{
    meta:
        id = "6o5m6J34DSmuTogkFkoFmi"
        fingerprint = "b85b2925e53302dcb2b2881cdb381b46aa9056daad481bccaf9b65c10c97dce9"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="030b0c393eb8a601c800cea0054fe334"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="d718adbe2a6fc8242442da6dfcf4f7a0"
    $a3="710c980e55faa60837d875fba41ed45e"
    $a4="d9d247a789f19a41659c6611240e10e0"
    $a5="e7d21aa3a0517f3395583852f8b6556e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}