rule blake2b_hashed_default_creds_liquidware_labs_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liquidware_labs_inc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="143a67efd513122ca7646c83bcf7cb0671a5575ebe3d5afee3a3148351fdb1038c687ee51236823f361fa9e3b1b35ef3d6317fbd31e78681a58613be2407419f"
    $a1="bc457c419235100068e394a18b35cfa0a33ba93582441d427d84421fef6537cc873c58783939f3942a2c736ddbddde5caa0073859f6e2a3e9bbd9013d2262c4b"
condition:
    ($a0 and $a1)
}