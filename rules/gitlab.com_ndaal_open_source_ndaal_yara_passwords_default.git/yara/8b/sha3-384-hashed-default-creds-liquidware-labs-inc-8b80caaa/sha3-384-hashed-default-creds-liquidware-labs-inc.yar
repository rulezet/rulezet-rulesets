rule sha3_384_hashed_default_creds_liquidware_labs_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liquidware_labs_inc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c8f5864ccd4c0bea7bde3c20a4d9b1b225a4725e18a8e440338fbf77fda53028229d3f22a51302b1f18196f4e05fe0d8"
    $a1="6fccb029278d6f571eda2a5ba309343c91bf0728a23722dc257aedfb2fe5a0023f9f36935049a0497eebe75d2db3b31b"
condition:
    ($a0 and $a1)
}