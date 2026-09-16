rule nthash_hashed_default_creds_nai
{
    meta:
        id = "na0i8TWrRHMwZFmWJePLM"
        fingerprint = "b642403c1ea052e0f4377368f398a1c57bdb259bfa99c1a8e19a04fadaffb789"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nai."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3dde58b5ce6a919c3cad61398f2cb61a"
    $a1="3dde58b5ce6a919c3cad61398f2cb61a"
    $a2="3008c87294511142799dca1191e69a0f"
    $a3="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}