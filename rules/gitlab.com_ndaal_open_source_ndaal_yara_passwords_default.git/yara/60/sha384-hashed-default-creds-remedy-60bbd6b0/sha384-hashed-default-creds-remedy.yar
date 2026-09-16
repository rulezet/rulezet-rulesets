rule sha384_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99e25df9a9df23daf6c88b3d6026b406b0317189bc7b46d017aae3d9ea3f934747ed17c1b19d25b81cf75ccef57af520"
    $a1="e6578b5e0b2b7765deee809fdcdb776cc1887958830aad0894e76b62d56c1872a39252877cde9d8964fa8e00c446843c"
condition:
    ($a0 and $a1)
}