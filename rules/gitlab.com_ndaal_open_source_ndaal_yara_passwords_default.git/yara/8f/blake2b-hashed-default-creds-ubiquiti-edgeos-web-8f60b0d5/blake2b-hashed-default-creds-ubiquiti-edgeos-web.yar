rule blake2b_hashed_default_creds_ubiquiti_edgeos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti_edgeos_web."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c087c9aeff4d51b3a6156d4e53950d1a96d07b8904a75e9d8a23c4d1d3af4e6fb49325ac7cda6dee257b5cfcb79ba6c8de296eb425adaf488f4f0aefd8b9dc72"
    $a1="c087c9aeff4d51b3a6156d4e53950d1a96d07b8904a75e9d8a23c4d1d3af4e6fb49325ac7cda6dee257b5cfcb79ba6c8de296eb425adaf488f4f0aefd8b9dc72"
condition:
    ($a0 and $a1)
}