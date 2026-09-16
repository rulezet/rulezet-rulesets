rule nthash_hashed_default_creds_the_qbittorrent_project
{
    meta:
        id = "4uQxl2JHibbogIlIyqNaY6"
        fingerprint = "8d5eba92d2002ba510ce4e4f32a302769acf20977fd7d827b619cf0aac78adde"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for the_qbittorrent_project."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3e126da93e034356d4e8cc3e0dd24357"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}