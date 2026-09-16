rule nthash_hashed_default_creds_asmax_ssh
{
    meta:
        id = "58HElfewvx3Ux9LylmoUhi"
        fingerprint = "5872c7ec9f9d4885c13ff693ef82191b391df93edd734c1d68b3001c028ef133"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asmax_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="1e1dd34b128de1968a44212e05d9e942"
    $a3="1e1dd34b128de1968a44212e05d9e942"
    $a4="57d583aa46d571502aad4bb7aea09c70"
    $a5="57d583aa46d571502aad4bb7aea09c70"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}