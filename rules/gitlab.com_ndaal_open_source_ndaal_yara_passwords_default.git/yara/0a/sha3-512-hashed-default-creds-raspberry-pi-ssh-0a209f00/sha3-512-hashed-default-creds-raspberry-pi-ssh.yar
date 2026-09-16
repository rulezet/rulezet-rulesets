rule sha3_512_hashed_default_creds_raspberry_pi_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raspberry_pi_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca136c8b28613d271becc9635f4f507c91756d5f76e4b31717ebd8bf0a32ad87813d3b665b77c189ad6bf06d1795b978f37f46b512f39e232acbfe8c5175dfb"
    $a1="695457a7c7d5d016e0145db5dfabb3b2790aca7acc016bb9aa4e1a392ba09b43b715010134ec05b3d09ed2849e6e1509c8aa307726b7d9058316c7584d7cd285"
condition:
    ($a0 and $a1)
}