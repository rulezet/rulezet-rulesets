rule sha3_512_hashed_default_creds_adcompletecom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adcompletecom."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d69ed22fc52c139e82a80cc63208adbd2a31adeaa357f5e901beb63fccbc714adaf5df724f845ea783cb91baf574c146c85c13ee2d8ce40745f06a2a65441b9"
    $a1="5d69ed22fc52c139e82a80cc63208adbd2a31adeaa357f5e901beb63fccbc714adaf5df724f845ea783cb91baf574c146c85c13ee2d8ce40745f06a2a65441b9"
condition:
    ($a0 and $a1)
}