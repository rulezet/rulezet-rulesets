rule sha384_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e4cc99dea57495940c4bee645c016f3088560c42259cdf8fc7edc4db43a0190f5e60c84023802b7797cb6ceb0f7aeb3"
    $a1="7e4cc99dea57495940c4bee645c016f3088560c42259cdf8fc7edc4db43a0190f5e60c84023802b7797cb6ceb0f7aeb3"
condition:
    ($a0 and $a1)
}