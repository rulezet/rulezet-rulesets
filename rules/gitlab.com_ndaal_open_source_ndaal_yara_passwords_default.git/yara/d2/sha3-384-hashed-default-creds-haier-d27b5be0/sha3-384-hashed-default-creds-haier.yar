rule sha3_384_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d2f2b079e688a30b4c5f9c141f4e12f23c227ff9381b979645cc92194c29d42eb1eb8c4e116e6939c6f8c27a89c9cb4f"
    $a1="cd108cf2b457e1bc09bbe0a2d513748d9be05f4b392c8c5db53512557fd34588e030cd91e0518a6e4d31e1444c889999"
condition:
    ($a0 and $a1)
}