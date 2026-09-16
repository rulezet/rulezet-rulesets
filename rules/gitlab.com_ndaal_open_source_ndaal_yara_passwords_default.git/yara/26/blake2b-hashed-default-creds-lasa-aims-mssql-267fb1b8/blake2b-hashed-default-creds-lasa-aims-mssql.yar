rule blake2b_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="276d88d0ec2a613b3b2dc0d6a0e111e09f7b2f7954c9b0b675779da3f2ec536d895f50845bf054d34741caa34522028927d9c5b85014720175c488089b0651d6"
    $a1="c389a08ca48765ed7f0303e1823e4c20adf79b08368733b97fcb20b7c23d41e7487f826b4ee7c9c66b8e9d5ea50021271add19e347bfbfe0d5c6a053cf848589"
    $a2="276d88d0ec2a613b3b2dc0d6a0e111e09f7b2f7954c9b0b675779da3f2ec536d895f50845bf054d34741caa34522028927d9c5b85014720175c488089b0651d6"
    $a3="5de737932b1842eb2c7132ac46dc2412a6a3b28b684b4f18cf00d37518739fff9418b7c337db0edb2b909e8a4fb5003e4dfa1673b6af4d14f7ed0ec3257b931d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}