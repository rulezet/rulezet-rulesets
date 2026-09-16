rule sha384_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="14a80bcb82e085a28b4f555a824f607761893ccf140bd48b4226862f27ebeed742f8025e83dae5bf3078d228efa5e9ea"
    $a1="531a9ebc5892bffcfe960b8d9aaccedd5a769125093014991f9fc013aec215c82439570c5449c8afb6c3bfe80474ef72"
condition:
    ($a0 and $a1)
}