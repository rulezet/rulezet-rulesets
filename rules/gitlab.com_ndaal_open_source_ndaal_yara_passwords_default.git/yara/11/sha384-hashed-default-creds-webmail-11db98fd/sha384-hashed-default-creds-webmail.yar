rule sha384_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fda1ad15cebc440f1ee1cf2ad9e461ac118f0cd18b4c7606e2431b9f99299ad0f0c74ce4e3c3ad82e77ec0490c8cd219"
    $a1="dd4783315f6cd993fb4fd1782fa139985f2e7d769ba7913db01b1838b395f439dad3e743fd36c4c893253d7537f88dfb"
condition:
    ($a0 and $a1)
}