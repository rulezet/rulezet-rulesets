rule sha384_hashed_default_creds_quest_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for quest_software."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ead12ef786610814658fb8eff64a151bbde6a956e21e4302754a84dbb93dde46ca8952e17a0c93f61d40b6ac7211252c"
    $a1="ead12ef786610814658fb8eff64a151bbde6a956e21e4302754a84dbb93dde46ca8952e17a0c93f61d40b6ac7211252c"
condition:
    ($a0 and $a1)
}