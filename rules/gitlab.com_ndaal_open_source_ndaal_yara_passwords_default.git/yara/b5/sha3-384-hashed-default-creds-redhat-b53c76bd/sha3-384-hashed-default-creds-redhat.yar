rule sha3_384_hashed_default_creds_redhat
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for redhat."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ec04f04d710b2de223919f3d43a6fa24231f1fcc742732a371f488ddf1bb78affcee4317ce736aec28082c9f34c14e92"
    $a1="ec04f04d710b2de223919f3d43a6fa24231f1fcc742732a371f488ddf1bb78affcee4317ce736aec28082c9f34c14e92"
    $a2="a73cf129eac67f6b9e2f3818b3b845572914c3c6821fafdc71d834f7852ba1c1d894c1a1d71669b9090d1a08418d34d9"
    $a3="ec04f04d710b2de223919f3d43a6fa24231f1fcc742732a371f488ddf1bb78affcee4317ce736aec28082c9f34c14e92"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}