rule sha384_hashed_default_creds_tert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tert."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dc4e750d0525009efdc9e0f4af26ae723a597f8ed353712f800c66cc8a1c9fc97cf75ed14dfab17f61098ed6153bc5ae"
    $a1="dc4e750d0525009efdc9e0f4af26ae723a597f8ed353712f800c66cc8a1c9fc97cf75ed14dfab17f61098ed6153bc5ae"
condition:
    ($a0 and $a1)
}