rule sha1_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="956c8a9c5dce43c1901f60bd6f87ff00dcb3ded5"
    $a1="3f282fcba8933e03a65a6dc92a27de8396961e2f"
condition:
    ($a0 and $a1)
}