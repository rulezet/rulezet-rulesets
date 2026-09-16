rule sha512_hashed_default_creds_merit_lilin
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for merit_lilin."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="31706de34b1001332309c6a401e28efceb38bae500ca98de6a70fb5ab82c16ab1ebfc1f5169b0f849e7b6e19c68258c8fa4dbe5cb9a36c293149dda163b48695"
    $a1="27acb043743923730f454b7f017bba1d17d0343cc255db05d61fa3f82330413026d7007e56c28c5797fbe5204b3a15ee031f98fb3b023abdbcfc380a7f90e955"
condition:
    ($a0 and $a1)
}