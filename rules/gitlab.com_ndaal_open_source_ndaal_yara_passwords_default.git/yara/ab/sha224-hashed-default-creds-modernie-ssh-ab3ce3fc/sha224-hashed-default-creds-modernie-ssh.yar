rule sha224_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eb11768af6e89759ee9aa33ced5659362dead5f702c6441339e86239"
    $a1="01fc824c9cfa6ab1597d349b0e0cbb60983375278a990d2b7529a997"
condition:
    ($a0 and $a1)
}