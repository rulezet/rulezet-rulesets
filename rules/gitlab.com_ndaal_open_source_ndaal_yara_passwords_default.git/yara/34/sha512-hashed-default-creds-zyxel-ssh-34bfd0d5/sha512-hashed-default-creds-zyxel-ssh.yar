rule sha512_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f628ac307c494ab7620b51935842da4d18b1a150910133b39438cf551745753920dbba90515487e33168e917002b45ee73cded3014e9cbec09cee0f736d11fce"
    $a1="ac190ec2765fe303f43f1f5aae982aaa64f0c701a19d6e540ff421d4d53b347c7dd784620b8b030c315bde81a0587adbc387a7a270e76a096126df8dbd7fbd8e"
condition:
    ($a0 and $a1)
}