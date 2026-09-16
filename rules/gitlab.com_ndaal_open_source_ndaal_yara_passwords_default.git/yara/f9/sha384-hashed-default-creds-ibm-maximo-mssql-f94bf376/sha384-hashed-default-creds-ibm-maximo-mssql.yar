rule sha384_hashed_default_creds_ibm_maximo_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_maximo_mssql."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dabe7e42cb76b9ce673f2830d09dae787a250d6e7d48a32d82e9784271f44f62c3e780cdd2c703959c9abc276afeaaeb"
    $a1="dabe7e42cb76b9ce673f2830d09dae787a250d6e7d48a32d82e9784271f44f62c3e780cdd2c703959c9abc276afeaaeb"
    $a2="483b7c82acf22a47e5ced3d4cdeed9083e3aee2ca5b8432f5aa46f434ec6c376bebb4a1dddcb97dd93d75d1bf001651e"
    $a3="483b7c82acf22a47e5ced3d4cdeed9083e3aee2ca5b8432f5aa46f434ec6c376bebb4a1dddcb97dd93d75d1bf001651e"
    $a4="24bd64f280f3a90a64d2f41964a086dab5ffd0f536a8028c7c6d143abf3f8a5774099de9b7fc318b31ae1e7547d04b4b"
    $a5="24bd64f280f3a90a64d2f41964a086dab5ffd0f536a8028c7c6d143abf3f8a5774099de9b7fc318b31ae1e7547d04b4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}