rule nthash_hashed_default_creds_lockdown
{
    meta:
        id = "71v846FY0qYGvym7Qd2pJ0"
        fingerprint = "96f8b75b3f307068ff78b235136cd86a50f6793ad4695ab18546ad2629b5ed92"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lockdown."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cfcdc7e09d8611201e7a4372b4d3a249"
    $a1="e6aebf95ee750d35a58d279ad1fbf32b"
condition:
    ($a0 and $a1)
}