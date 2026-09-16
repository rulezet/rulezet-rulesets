rule sha3_256_hashed_default_creds_server_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for server_technology."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2ae77b32c212533eb7805f83d4f45fcdfb4f8da4eea248a088b39b1637172b81"
    $a1="fe8783e1c9c081a507b7d28f520d292ef62ac464f40660dd5823ea30ef14eec3"
    $a2="929cdb8bd0dd2ab6488acfc24fe92c336e3d9bb0df0299f25898cee9fea3b9b4"
    $a3="c1aad3f30824c27683b44fc984e22b51a5a0b28b07ee1993dbf763c66fc656de"
    $a4="ce8dbacfdbbc77c351b6c1080f01a4f6313d8788afb345ed590f93051851685c"
    $a5="4684eed63157311e7581eb9c6cda94f88d1bf05007dee882af34d3781538b9e1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}