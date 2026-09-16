rule nthash_hashed_default_creds_bizdesign
{
    meta:
        id = "17z4ttecvdKu13WK5cIL42"
        fingerprint = "8d27ff76f6291270c78e2d38ed4537ce2face244073ae39ba439bee7e8d31371"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bizdesign."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="395491df308448a7ba9fbddeb6046324"
    $a1="a25b2710ba9de114396adc7dfb0a7235"
condition:
    ($a0 and $a1)
}