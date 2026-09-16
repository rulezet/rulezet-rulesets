rule sha3_256_hashed_default_creds_adobe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adobe."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="6913426a18b7a2b8e1e56901ce29f4cb4591ac0a6b16293bf89a9996979bb8c0"
    $a3="6913426a18b7a2b8e1e56901ce29f4cb4591ac0a6b16293bf89a9996979bb8c0"
    $a4="36e7a2865de35667ff62ee2b3c9135f8352a421a710f247ac927ebd11eff4393"
    $a5="36e7a2865de35667ff62ee2b3c9135f8352a421a710f247ac927ebd11eff4393"
    $a6="eaae764e4df8101af64d11ca89222cff01ce9f2a42bd24204972fb22da6f4df5"
    $a7="e1c7998de2ae401d0782b88a14ffa4cf36e91ba1fe419363c145f3cd257fea68"
    $a8="79dc6d9ffd8fcf7cf9fda7b560efe726de6c73591cf15f20435767fa444efa0b"
    $a9="08da9c451c836b31b52693eab161e2858ddd6e932fdeaff1da75249db3fc46ef"
    $a10="740626735fcb2bc2e6d1d053a08839e662e1b742c48f6b66e6ba3d0a0e5b0149"
    $a11="740626735fcb2bc2e6d1d053a08839e662e1b742c48f6b66e6ba3d0a0e5b0149"
    $a12="6d26e46be53f0fe7ef598ac735921bc632adafb06495e3cc8d5b8a000d2a43a3"
    $a13="6d26e46be53f0fe7ef598ac735921bc632adafb06495e3cc8d5b8a000d2a43a3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}