rule sha384_hashed_default_creds_360_systems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 360_systems."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a35e580c5e221b1031137ad24f272e05cceb72d5f7f6821320e7ba0a883154491948600073e063ef9d89a91887775aa2"
    $a1="a35e580c5e221b1031137ad24f272e05cceb72d5f7f6821320e7ba0a883154491948600073e063ef9d89a91887775aa2"
condition:
    ($a0 and $a1)
}