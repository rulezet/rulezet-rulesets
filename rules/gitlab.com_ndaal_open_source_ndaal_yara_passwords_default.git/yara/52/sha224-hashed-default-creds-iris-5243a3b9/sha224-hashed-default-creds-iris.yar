rule sha224_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
    $a1="fc0b76a91e726f60f4ecb31ebc3d213fdab48350dba4eeff039c71f7"
condition:
    ($a0 and $a1)
}