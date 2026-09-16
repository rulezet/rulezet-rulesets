rule sha3_512_hashed_default_creds_solarwinds
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for solarwinds."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="67b2b2177230db288d569c9e6f5da57aade688d99bf7deebc64588297e6da6d3f00012bd325ab2b216ff0807db4477084360e4caf7fe9f2c1460566ee8bd0f39"
    $a1="2346b577ce31549a777a561f0864855f33c1788af1221756730baac301dd34ca493607f1d0f87f08a8312b4b3fc14260935ef5c523112b11932566056ea66afb"
    $a2="a546615347becb5b0353590b2811e6a6a8117c9abb42f71451195792c5cbfcb5c6ed9f79a6b0bbd0def2ccef3ce39170c2826aa2bda926cc19cfe70b480991d1"
    $a3="a546615347becb5b0353590b2811e6a6a8117c9abb42f71451195792c5cbfcb5c6ed9f79a6b0bbd0def2ccef3ce39170c2826aa2bda926cc19cfe70b480991d1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}