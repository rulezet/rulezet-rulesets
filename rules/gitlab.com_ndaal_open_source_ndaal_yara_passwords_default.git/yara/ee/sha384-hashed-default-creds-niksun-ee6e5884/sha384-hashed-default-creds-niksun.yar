rule sha384_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="736310e9279ef220a4c499f59a932031c5a6d3e401059881e2c521a77d2a201824dd901a75faf060e5c0f68ccb3e1f64"
    $a1="9a2134f0b7deb5a770e1ad6fb875a6cf6012d933c855682917aa5d5da84c1d39f48f8d3f57101aa488ee091d6a300ba3"
condition:
    ($a0 and $a1)
}