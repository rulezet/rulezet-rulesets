rule md5_hashed_default_creds_symmetricom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symmetricom."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a35db48f859b9e1f3db01e82686c8917"
    $a1="084e0343a0486ff05530df6c705c8bb4"
    $a2="abe10f7e5afbbb3a79ce619739541149"
    $a3="4b583376b2767b923c3e1da60d10de59"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}