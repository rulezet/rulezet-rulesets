rule sha3_384_hashed_default_creds_canonical_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canonical_ltd."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f9105392ddba90b550075ea2e4a2dec45cde704972976e2a52897c30836357580a1b8a024ee51701609358abf426a9c"
    $a1="5f9105392ddba90b550075ea2e4a2dec45cde704972976e2a52897c30836357580a1b8a024ee51701609358abf426a9c"
condition:
    ($a0 and $a1)
}