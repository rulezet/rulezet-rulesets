rule sha3_384_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="192b8ac3fb4eb32cfc08fb7523a714fdcfd31e8fbb314cd447b03022f041271f8cb64a58f1c11c7fd14e1354e2b04ba2"
    $a1="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a2="192b8ac3fb4eb32cfc08fb7523a714fdcfd31e8fbb314cd447b03022f041271f8cb64a58f1c11c7fd14e1354e2b04ba2"
    $a3="0b57b7df1323cbbec47d05bcdb1aeea4c7e0b0936928ad838b3330ebd8d0e6d109264aa25d705c16a975d4bfc2c8628d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}