rule sha384_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c2cb5263ddda99080396ff9ebd4c7bdd9fbda9dc80f4d2ca0ed6985e1f3ea176b5c40c5b4a027f0da5f9438c0d386c41"
    $a1="4eeda022ea59d7665ef784ad3bd557d36dc88c58a1e1dbbe4cb49081db444783318775baf0a11048eaeb9ae6d87bfac3"
condition:
    ($a0 and $a1)
}