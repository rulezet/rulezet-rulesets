rule sha256_hashed_default_creds_ibm_imm_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_imm_web."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="edd878f94bafc7a4e96cf4fafbc9e9cf7bf9b846382127a001a3149f654c4d65"
    $a1="0d9fed9bd1ee63b55cfb1a695f80a3d11caba9477f3d7ac39d18ec3f11dc696d"
condition:
    ($a0 and $a1)
}