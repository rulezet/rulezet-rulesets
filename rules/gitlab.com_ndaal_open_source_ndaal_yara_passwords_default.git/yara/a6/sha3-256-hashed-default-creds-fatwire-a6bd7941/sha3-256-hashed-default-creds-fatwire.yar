rule sha3_256_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="098857c2f2f3b2db6eb8fd4b6b8be8f0206a1c75a6e2e777e6a1bd8e7e51dbf3"
    $a1="098857c2f2f3b2db6eb8fd4b6b8be8f0206a1c75a6e2e777e6a1bd8e7e51dbf3"
    $a2="407eb2d8f4d42912977052bf56ba176a2f615f05089a7894a9917657d6a0b3e7"
    $a3="3deaf0f9eca5490e120d9c3a1bde7165ddf9f56a131de22224b184b9a1fe8238"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}