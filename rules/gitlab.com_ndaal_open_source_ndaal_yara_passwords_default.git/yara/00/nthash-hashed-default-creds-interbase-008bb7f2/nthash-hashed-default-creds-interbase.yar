rule nthash_hashed_default_creds_interbase
{
    meta:
        id = "1XPxujVkZBrNuyW46nvzMI"
        fingerprint = "00051dfdde50386b975cda69d2b997c380379be4d05059687f9b28a52e22c323"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cdcc7a35d120c4f1c5da1422a4201708"
    $a1="c3d0be8b1416fb84e6cd4954431d5414"
condition:
    ($a0 and $a1)
}