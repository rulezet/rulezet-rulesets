rule nthash_hashed_default_creds_pbx
{
    meta:
        id = "71zydpqSTzcu2iseG9UuD0"
        fingerprint = "c76b05521acf8f8f9bd41067bcfa7fe3b8da4e0e08bc1e745d64f38d6531b27f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pbx."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e360985733008b39ad07d2563bd6d656"
    $a1="06da4042f45ed8e9a8d0574b0437c14b"
condition:
    ($a0 and $a1)
}