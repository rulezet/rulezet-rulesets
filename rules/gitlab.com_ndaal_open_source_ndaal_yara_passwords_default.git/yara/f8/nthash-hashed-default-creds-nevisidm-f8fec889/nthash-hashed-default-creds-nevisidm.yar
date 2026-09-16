rule nthash_hashed_default_creds_nevisidm
{
    meta:
        id = "3voRge82FwhxTUghpHdhBg"
        fingerprint = "8ad9b133b8f38205c8d1bbce33f1ce4ec8717f90c6c91f793c84178103c97473"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nevisidm."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e2310ec4062a717524219d454dff6e19"
    $a1="140bcf2c1f90db9783657e3ddbaf5fc7"
condition:
    ($a0 and $a1)
}