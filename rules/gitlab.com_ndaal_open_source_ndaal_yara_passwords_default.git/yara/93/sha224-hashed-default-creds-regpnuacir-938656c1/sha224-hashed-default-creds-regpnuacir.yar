rule sha224_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="16a72b36ce4d3ab7d58f2e11d445bd81725e2960af2160b40d010eab"
    $a1="773b7e92797eb2f7176cc82ae23d252d971739eb2f029e33abe767e7"
condition:
    ($a0 and $a1)
}