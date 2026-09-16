rule sha1_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a1="6653cefd5d2ddc4c2bc26b75fc09dba80b181b13"
    $a2="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a3="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a4="1bfe152b965a4a3bcc493fe26b46fdf00509fa83"
    $a5="bba2617056f3ad9b1aaebd2df10c0e69cf4f647d"
    $a6="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a7="9a27718297218c3757c365d357d13f49d0fa3065"
    $a8="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a9="f3a929b3364b471a481f4f7cda0b4559ecde9aba"
    $a10="f3a929b3364b471a481f4f7cda0b4559ecde9aba"
    $a11="f3a929b3364b471a481f4f7cda0b4559ecde9aba"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}