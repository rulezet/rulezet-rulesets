rule sha3_512_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="48d21c54186d08dd99513469a2eb87a2afcc3af0f25250ee7aa67802beb27dcd76c743e2c68d38d2fee41118629fdb943fbc13ae43ddcda32524caf9dd790755"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="fb34a7db3856065b1b3cf22df94cd087e62cd3200ef7588f0bfd59e9145fb49d70648f0e0e57acedd1a1adf77ebfc564060c082069b35025adc6fa87dceca8d0"
    $a3="a0e03c7f9cec389616c03d3b59f3a51f33b140ebca5055e5ebc7170351aa97984fd4aeb8a7bb25016159b43b13c8438f51306902dffb5aafd592bce5ef92349f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}