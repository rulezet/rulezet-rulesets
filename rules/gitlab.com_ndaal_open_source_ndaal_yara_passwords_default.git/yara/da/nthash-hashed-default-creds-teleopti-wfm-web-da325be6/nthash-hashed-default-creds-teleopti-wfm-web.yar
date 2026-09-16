rule nthash_hashed_default_creds_teleopti_wfm_web
{
    meta:
        id = "3mZvPXhi4V3Z8w3PE45xNS"
        fingerprint = "afee1718e83fd388e1de78e315c4c88e716773f93919271a3d91f16278e66e02"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for teleopti_wfm_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="e9fb2c28883721aa1eabe56150e3cc39"
condition:
    ($a0 and $a1)
}