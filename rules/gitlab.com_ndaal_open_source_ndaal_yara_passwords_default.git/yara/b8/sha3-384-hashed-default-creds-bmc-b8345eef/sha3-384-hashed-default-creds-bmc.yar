rule sha3_384_hashed_default_creds_bmc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="968951d5d06f5dce1d93b83ea0809953fc5ad70b81ac6c36d6cce23bc29c76d121f3cfaffca16c8604cdc5a554f0d340"
    $a1="968951d5d06f5dce1d93b83ea0809953fc5ad70b81ac6c36d6cce23bc29c76d121f3cfaffca16c8604cdc5a554f0d340"
condition:
    ($a0 and $a1)
}