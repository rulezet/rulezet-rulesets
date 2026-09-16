rule sha256_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f81474dd5c6fdfd0b86d874390fa7e5b960e29c4f7f1e860635ac3bc5e32a897"
    $a1="97eab8eca5407fe0bd1af1eb4f1e4fe0c4760ea48aef889803ac7584586e2cdd"
condition:
    ($a0 and $a1)
}