rule blake2s_hashed_default_creds_solarwinds
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for solarwinds."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="26cf3984aefc77bf032a81cdf879a739a1ec5fd3758c0c611c1b4c7a89f8c8a1"
    $a1="af69e6ac5c39ed89b709a19cf1c211421cbee5dd355269d856a6426e28c55e2b"
    $a2="593e27c355373e852313ac66568b7ab72b9570c2a695493a3444607079c98341"
    $a3="593e27c355373e852313ac66568b7ab72b9570c2a695493a3444607079c98341"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}