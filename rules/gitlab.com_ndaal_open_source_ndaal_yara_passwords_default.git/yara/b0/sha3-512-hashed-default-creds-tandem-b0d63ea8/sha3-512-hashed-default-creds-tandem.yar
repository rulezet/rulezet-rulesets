rule sha3_512_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c56f59716f146eba7b862cf6a1443e68a3cee348bd8a6d51dcaa1ea5c52b41692ebca2e96063db57158e82f789a429d2723b0d84c3a308e198827399448c9090"
    $a1="307f61f0093091ee4a20eef27ee7094924327ba1b6690007150283abe162c47a2251742dd69e897d5eae457a6833e4a32d373152afec55c93baa769b54825a5c"
condition:
    ($a0 and $a1)
}