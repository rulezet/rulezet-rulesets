rule sha256_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="29761b5f5508f92ef28a1712097d4dc0ff1ae7ad35f1f0ab233d151fac351ff3"
    $a1="644a6d40e00843025bce83ec8c2311d17c6d2b6a3a2ba0a917815cfd9515bb1d"
condition:
    ($a0 and $a1)
}