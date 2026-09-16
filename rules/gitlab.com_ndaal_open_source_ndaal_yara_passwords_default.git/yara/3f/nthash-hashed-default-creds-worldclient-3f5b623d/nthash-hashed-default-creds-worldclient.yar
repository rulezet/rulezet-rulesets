rule nthash_hashed_default_creds_worldclient
{
    meta:
        id = "7DeyGaGr9eWrZGvpFRk0cJ"
        fingerprint = "05d0f2008f3997cef0c9dd7202c5b06e580d05d6c4e2991ed7389550a0846d7e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for worldclient."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a25b2710ba9de114396adc7dfb0a7235"
    $a1="af62387d97bc187df65ba77fa0d55881"
condition:
    ($a0 and $a1)
}