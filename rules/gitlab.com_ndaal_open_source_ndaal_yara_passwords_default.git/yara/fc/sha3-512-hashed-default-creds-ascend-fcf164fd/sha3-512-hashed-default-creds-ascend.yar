rule sha3_512_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="17e9de94a290a315ec0e256d5075c1180d0e103275e1ea169e3c0fadee41b5891c50df88b6c434eae0d6ea7a2d9abfdaa1b0163ca8baa6587b2fd38618c9f583"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="830da7fdae27f65e0604953d955bdc20f007c6cbbb2a807cae31d88cef2403516d6c5f7a656f47eafc376cf37127fa824e115f7b34db333904354490edea6292"
    $a3="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a4="77e103fa4098a3ee23c73bec9df9561b0396fca97097342fbf7fe7dc1c489b401baa6153933443b204fbc19a5c8154b1e1ff2014242ff9a181f92926d49fe4b4"
    $a5="a042b8def54466d33a9fa2de436041aac98bb190a245f7829b0f1ee858568e115ebb963491f5aabbec1e69d7deee0bdcf846bc626029b59ad517f520aa6a8f21"
    $a6="a74fa0d922a306eb09a5cefed65b4165387ea013cdcc19ed7ca7a5d32a4bf9e594f18d28e3127e715593e3b9cd57bce95be5592ca580455878daa1cdceefbcb5"
    $a7="0932668b8444d7cc4c45425e8a81d3e4b857045672c7dfd99aa0937aaf86f4ceeb80af7e6845120b7ff6ff482d5ba4513f4b65b76c5ee2f2e2f037ac874ad4cc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}