rule base64_hashed_default_creds_fortinet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fortinet."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bWFpbnRhaW5lcg=="
    $a1="YWRtaW4="
    $a2="bWFpbnRhaW5lcg=="
    $a3="YmNwYitzZXJpYWwj"
    $a4="bWFpbnRhaW5lcg=="
    $a5="YmNwYltTRVJJQUwgTk8uXQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}