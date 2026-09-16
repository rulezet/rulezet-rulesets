rule nthash_hashed_default_creds_schneider_m340web
{
    meta:
        id = "NI3BqrY350v4nEpDsmf75"
        fingerprint = "a7d85bb55a2457bcc1852b354185d0fb1cc63b68c6f7c96b3e6f3a60b64ee518"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider_m340web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="467799ec546cddb461f187080eebb40b"
    $a1="467799ec546cddb461f187080eebb40b"
condition:
    ($a0 and $a1)
}