rule sha384_hashed_default_creds_liquidware_labs_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liquidware_labs_inc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cd049df322769f6ed74fe359a60cf6891469fb24c7e8c10bb43c07c277fb0ca1d065cb9afd925fc252f508aa23d30283"
    $a1="0154f64bee08cfa1ff3d89190186e96709d8e46415e0e844bd66225896fa10d4373446307d147ec42eca51436aee8e19"
condition:
    ($a0 and $a1)
}