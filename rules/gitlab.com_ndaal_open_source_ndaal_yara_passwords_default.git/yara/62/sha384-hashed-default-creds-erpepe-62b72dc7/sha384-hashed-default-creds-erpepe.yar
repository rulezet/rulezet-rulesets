rule sha384_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1f7b7c33aaf24635f11e2827b288ba4af717b0c30d94c3df01744fcb76a2722d63b032867aa7416d88cf5fa6c62995b0"
    $a1="0948c7666159edd3bbc76393c4ded1465caae34ca88fcf7e40331f0c56e818e13d788d7028af4714b65c55f4562559c4"
condition:
    ($a0 and $a1)
}