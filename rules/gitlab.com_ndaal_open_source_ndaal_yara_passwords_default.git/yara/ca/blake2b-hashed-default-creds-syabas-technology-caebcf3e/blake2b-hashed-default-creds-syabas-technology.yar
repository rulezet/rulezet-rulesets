rule blake2b_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="da77bd2a1d857d88b31de27536b81df7f005027d4f847667df13a0569b6048e0454ce9480827789547cc174060c4f388866ebb0209929b0de414cc9ac571c421"
    $a1="ff1d879655fdb53a4290b756b5c3c12cffc056992be06705fc6983782102a88c3bb1f1ac797792a7133ccb03610816d350a15a2c1cccc7d4d477560c2226e3f0"
    $a2="da77bd2a1d857d88b31de27536b81df7f005027d4f847667df13a0569b6048e0454ce9480827789547cc174060c4f388866ebb0209929b0de414cc9ac571c421"
    $a3="9dafd721a28b9b2bcc2fcd3a9218a9522e69260dc216e4f036cebd2513e2e08309b5560cbd01c33792de736ec97d777bfec9479a625f0e59256c7e9e92b49950"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}