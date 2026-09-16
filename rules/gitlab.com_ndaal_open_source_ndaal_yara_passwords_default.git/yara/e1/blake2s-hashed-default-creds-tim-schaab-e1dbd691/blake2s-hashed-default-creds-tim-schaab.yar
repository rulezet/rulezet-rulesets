rule blake2s_hashed_default_creds_tim_schaab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tim_schaab."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="efaf787dae80c58d0676abbda9990f95819db87e62549104485872f23f8ab5d2"
    $a1="f6bddb051aec6d01742704121def4365dcff3684356da6781edc4468cfed7e90"
condition:
    ($a0 and $a1)
}