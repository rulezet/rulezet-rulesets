rule sha3_224_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2181c1f89f533265b2e0d39a6d50e0b695f0b8edb55319effc618b03"
    $a1="67770354014920888f17f0f59ca504415087d0df75ebd7b0d6517b70"
    $a2="1e2919ffe3f0cb870be18c31bb9f3d3df9dad3983138c72d10ac3237"
    $a3="1b7e2482bc4d1b5828720925e9fc446aaf809d1779efe909343de13c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}