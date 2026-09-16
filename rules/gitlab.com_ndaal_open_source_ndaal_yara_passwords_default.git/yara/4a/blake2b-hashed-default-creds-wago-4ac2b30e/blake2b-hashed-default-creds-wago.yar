rule blake2b_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb5f9b463af982c8e64474ce3b34679ef60cfa2e895ecb11b6b9d0ccdd12ef1c7a1dd51c13a2580cdb6a074df98cac450efc6a134a4dcae5d6a634e28281e5e7"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a3="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a4="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a5="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a6="1e9cae59a51fc6b2d71a5d5fa4bcbb07df23d87f1fcb2997d4982b7ff410cd73b4ba347a3043f64c8ef9d2c2c375866a65269b0755175a0ae7c43295c1dc3db7"
    $a7="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a8="bd050c4d6a036e7022b6d3311934b19337999f07826078a1303ce0acc145efc9bebb09fd5266ad3cb6f5728ce71df28ea7160cdb78ddbd6b794dc7583b414b6f"
    $a9="efac5090bb3c1ebf872bfde6e526769e3b5bc5ad581025fb3bddb54b653bd1d69e4b12197ddb85d14798d90250246764006be08ff13194aa5febd07eee5101b6"
    $a10="fb5f9b463af982c8e64474ce3b34679ef60cfa2e895ecb11b6b9d0ccdd12ef1c7a1dd51c13a2580cdb6a074df98cac450efc6a134a4dcae5d6a634e28281e5e7"
    $a11="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}