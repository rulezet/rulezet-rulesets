rule nthash_hashed_default_creds_datawizard_technologies_inc
{
    meta:
        id = "2L0bOV7tR98cNsyaNJDTUu"
        fingerprint = "ccea7e460d9ff211797bbd9a8f0ab438353d4662ca5c7822b3e7e45ad3d22fb1"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for datawizard_technologies_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0cb6948805f797bf2a82807973b89537"
    $a1="0cb6948805f797bf2a82807973b89537"
condition:
    ($a0 and $a1)
}