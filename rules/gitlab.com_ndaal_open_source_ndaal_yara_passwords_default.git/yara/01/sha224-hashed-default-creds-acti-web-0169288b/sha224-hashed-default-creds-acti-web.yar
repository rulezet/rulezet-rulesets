rule sha224_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a3="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a4="f8cdb04495ded47615258f9dc6a3f4707fd2405434fefc3cbf4ef4e6"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="f8cdb04495ded47615258f9dc6a3f4707fd2405434fefc3cbf4ef4e6"
    $a7="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}