rule sha1_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3aa33bd61de44302d50150f24d487498efeffb22"
    $a1="32faaecac742100f7753f0c1d0aa0add01b4046b"
    $a2="c95ee47689a0aaec70c3eb950244657722c69b1f"
    $a3="c95ee47689a0aaec70c3eb950244657722c69b1f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}