rule sha384_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c98f7893a47c432ae28e6024a345dff67233e1b54b2d1c73662c7b3eae567caf3ef5a2d2a204f8aa1290b64f869894de"
    $a1="1e85c366175990ec1eeea3dae48364fcb193f6e48b6fc073d46f001841d5aba3a6f93633ccac01a27ad96b1321e72158"
    $a2="625a921712f28a1567b1140b40f884869e62e23dd312b2984eed227692d44d53c50bbbccf718b9db42e2049b8ca730f0"
    $a3="1341b34f7c8e0fb7deb68b3da30c3cb30dee1809e52ef883536efb5e86d873bbb85a81407ea2f0abb68346644155736d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}