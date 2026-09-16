rule sha384_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fff4bdd8b80e7c90ffd86dfc002002eb0bd25127dc4650abf1db7c1fa1c20ac3221d96a80da8184dbd65475c8f974093"
    $a1="a62b2dab63428f6f0a7afb10c6c313b1b60efcd904128e4e57e90d142dafef00187676b61d93436975f7d3897e5b1548"
condition:
    ($a0 and $a1)
}