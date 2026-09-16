rule sha3_384_hashed_default_creds_toplayer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toplayer."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f3ac5428e5ab29e39a3a13e23348a5c7710ab5e94247386def74f64c861b917927b3d30190416561965ed47e0cf6624f"
    $a1="eb4bb1f4042e76b51e80dfaeb0d4d1d715fe9e7d3b61d97417df67deb643d809e45700b08540403fcb70ab1821492b3f"
condition:
    ($a0 and $a1)
}