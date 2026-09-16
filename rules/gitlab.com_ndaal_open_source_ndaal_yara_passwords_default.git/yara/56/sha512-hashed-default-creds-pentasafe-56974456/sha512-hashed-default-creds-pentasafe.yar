rule sha512_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bbb8c28d14e3fca965ebcdeac99f21c20aa66a3eba2aa8011f3428c00cd3bf723cac4ba7ec2593f4b398aeaeab53d7faf31e00d900d9ec8f0e7974b4259e208e"
    $a1="ddf008606d4eb46085ed7f482458c446fe9a948e8646c52e4cd91eb3f7dbdc55cdb40c891cead818f3cdbe4ad41e90c24cace8b4e9c56bfe50095dc84e0b2fe3"
condition:
    ($a0 and $a1)
}