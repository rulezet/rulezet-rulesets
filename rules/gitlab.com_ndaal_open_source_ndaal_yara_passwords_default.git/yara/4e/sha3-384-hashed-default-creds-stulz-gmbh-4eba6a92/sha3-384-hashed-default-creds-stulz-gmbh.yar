rule sha3_384_hashed_default_creds_stulz_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stulz_gmbh."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="89816b07552a9b46aa8f889c828320ae1617509c0eacb498831febb718a404cedb701a416b0c61e8a428a9e9ccbe12ca"
    $a1="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a2="53ecd2437e72380a7c71e8ee54728de51b9308d551d0b7339d6f1cafd6a63951254e8ef52f40972c2348f62a451ee153"
    $a3="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a4="1725b02d5d33574c7e559eca00b216e1dcfc2bf054cbf8a98ce0a9107a850828aeb667c612ed1df8f5c93e525e7b8ff4"
    $a5="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}