rule sha3_512_hashed_default_creds_davox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for davox."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="f8d6104d3a871b5a1755c1e17faf36b09307d8542ff7998f10a3827909ac07d51764966c4da9fd587f5f979006ad0cf230d3d8d46ab055658e5a5580437670f8"
    $a3="f8d6104d3a871b5a1755c1e17faf36b09307d8542ff7998f10a3827909ac07d51764966c4da9fd587f5f979006ad0cf230d3d8d46ab055658e5a5580437670f8"
    $a4="f8d6104d3a871b5a1755c1e17faf36b09307d8542ff7998f10a3827909ac07d51764966c4da9fd587f5f979006ad0cf230d3d8d46ab055658e5a5580437670f8"
    $a5="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}