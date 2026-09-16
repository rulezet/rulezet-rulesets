rule sha384_hashed_default_creds_jd_edwards
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jd_edwards."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="354e2762cb1981256970955effe084db746b5e41169db01452e2da88f0ec518f70b18a5de9961624075c56dfd52dacc4"
    $a1="354e2762cb1981256970955effe084db746b5e41169db01452e2da88f0ec518f70b18a5de9961624075c56dfd52dacc4"
condition:
    ($a0 and $a1)
}