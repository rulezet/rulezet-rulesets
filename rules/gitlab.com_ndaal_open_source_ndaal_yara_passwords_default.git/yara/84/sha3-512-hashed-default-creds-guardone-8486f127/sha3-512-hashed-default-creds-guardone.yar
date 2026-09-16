rule sha3_512_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="89ad8fdd72a8909f03f5fb53e309d26dc38a55d240620ab9034100e60c410edcf0c6f57771bad72f889f4a1e4dee4704741ec2082f85749540beb69cfa87f9e7"
    $a1="15a4b64a7d06755f56d0e82eeb2c3f4de7ee32f1f6c16647e04e43a71096f598fb4ed44a7f0c425289c4ba3c9d7bc8cae31a50e123a43a949878da526b833239"
condition:
    ($a0 and $a1)
}