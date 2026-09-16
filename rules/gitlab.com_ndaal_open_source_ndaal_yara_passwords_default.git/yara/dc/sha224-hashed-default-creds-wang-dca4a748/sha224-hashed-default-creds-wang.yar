rule sha224_hashed_default_creds_wang
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wang."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="945e396af7a6b4fa1940488100acb768c3b8ee8ba600a7f7309e8598"
    $a1="db3ffee338aef33c3ed7d2dd1585c067c05003890a702e2794e27afd"
condition:
    ($a0 and $a1)
}