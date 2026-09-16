rule ldap_sha1_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}2Oz1DQizD2jsyvw1Mrucn8xb3XU="
    $a1="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a2="{SHA}lgdjmu9+bL0qJ1fZ7+MwYijOgcE="
    $a3="{SHA}indhO0deRgZDIf19oY0SbuNeUGY="
    $a4="{SHA}lXt3tlplJsgwsXeZz4fmOe9sIw8="
    $a5="{SHA}1vdy+Id4siYm0rhioUpGFIGFd44="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}