rule sha3_512_hashed_default_creds_andover_controls
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for andover_controls."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="59913bcd65ed47fd2d61230418be7e92b0574e52ab186055ea99ffe68d39dc0b449fc12e627f34550770b0f748ee6e32cc420cd0005f7597a7d94d5404f74f06"
    $a1="59913bcd65ed47fd2d61230418be7e92b0574e52ab186055ea99ffe68d39dc0b449fc12e627f34550770b0f748ee6e32cc420cd0005f7597a7d94d5404f74f06"
condition:
    ($a0 and $a1)
}