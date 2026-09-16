rule blake2b_hashed_default_creds_cyberguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberguard."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ccf3cd03e24af503eaa93c3cc00fb3fdddc663b5d3f31aeb74541a36f59881d067e84c9662ad6fcaceb8d954d87709f923a1108f71fcca030c16d4a2b8cd3415"
    $a1="ccf3cd03e24af503eaa93c3cc00fb3fdddc663b5d3f31aeb74541a36f59881d067e84c9662ad6fcaceb8d954d87709f923a1108f71fcca030c16d4a2b8cd3415"
condition:
    ($a0 and $a1)
}