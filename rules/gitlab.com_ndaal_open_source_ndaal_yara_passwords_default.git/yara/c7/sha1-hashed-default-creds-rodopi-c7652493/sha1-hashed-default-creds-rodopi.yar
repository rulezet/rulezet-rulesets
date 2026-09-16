rule sha1_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="792fa88335ad9ee74ac403473cda50b23a7bc114"
    $a1="792fa88335ad9ee74ac403473cda50b23a7bc114"
    $a2="f4e65f2059efaed6379332d7e901159babaede12"
    $a3="f4e65f2059efaed6379332d7e901159babaede12"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}