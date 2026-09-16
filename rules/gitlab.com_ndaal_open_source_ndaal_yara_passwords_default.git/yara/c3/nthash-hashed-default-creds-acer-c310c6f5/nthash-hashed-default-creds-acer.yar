rule nthash_hashed_default_creds_acer
{
    meta:
        id = "39jb2sY1zpXh00Az6UmzCj"
        fingerprint = "64f15e13b49b590ed3bbc1723929f19dc89cd8752b7d68121c5df3324c01609c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="50b8c8aad511b8de23ff38a871f5fd03"
    $a1="50b8c8aad511b8de23ff38a871f5fd03"
condition:
    ($a0 and $a1)
}