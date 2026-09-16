rule sha384_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="504da0cfa732ceb7f99ac06c8074aa4e7b36621a10a15a428c1fbe43bfc43d810cf7d200999ba936f95474143ee2e375"
    $a1="1d684629cdafb4a4a107f99d3610ddb9b8610f8439e02b8431241370173194d73afd317df0df4af3a62d9316a1a611bb"
condition:
    ($a0 and $a1)
}