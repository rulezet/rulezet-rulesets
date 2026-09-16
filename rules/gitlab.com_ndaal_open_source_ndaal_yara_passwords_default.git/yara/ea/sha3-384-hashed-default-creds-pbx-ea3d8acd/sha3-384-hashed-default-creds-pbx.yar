rule sha3_384_hashed_default_creds_pbx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pbx."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="06f43f361da27725e96bdbfe0216a143dba6103a09d625140bbae64554a87495c7c6f67496e9e3abd1b676b7ae3da13f"
    $a1="3a742726566f6d65b11330667491a565ca4f74afa94ff04ef0e13b98fec6b50ec9efe4f779d45f90ce883367841ee691"
condition:
    ($a0 and $a1)
}