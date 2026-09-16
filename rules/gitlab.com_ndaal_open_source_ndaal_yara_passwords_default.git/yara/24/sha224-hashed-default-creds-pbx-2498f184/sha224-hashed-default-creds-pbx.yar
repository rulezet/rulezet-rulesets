rule sha224_hashed_default_creds_pbx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pbx."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eb90e1a292d4fe1f529dc54825471b629b53b96e2b533ddf9b317d8e"
    $a1="09fdbc623941c03d3cc3743c3f4923873e75ab6173375aca0500e2a0"
condition:
    ($a0 and $a1)
}