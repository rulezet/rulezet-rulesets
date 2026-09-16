rule sha256_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e2154a35f651ffdc5e041561b49e5ab1da0c9df346b7424c2ebaa9f09dbec805"
    $a1="2df53f17c2a6dab088a618a862f77528551344ec2cdcf5c3965eca8e070f5717"
condition:
    ($a0 and $a1)
}