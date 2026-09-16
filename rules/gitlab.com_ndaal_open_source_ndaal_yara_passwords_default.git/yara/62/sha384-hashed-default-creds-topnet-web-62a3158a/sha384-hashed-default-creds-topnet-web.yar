rule sha384_hashed_default_creds_topnet_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topnet_web."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="193b2c46210c4b2f5c97eb8a54f9b6ee5766c0c86a960e2d3ddf34a732da69b51f1e59e9c3e3584df1a90e9357d14014"
    $a1="193b2c46210c4b2f5c97eb8a54f9b6ee5766c0c86a960e2d3ddf34a732da69b51f1e59e9c3e3584df1a90e9357d14014"
condition:
    ($a0 and $a1)
}