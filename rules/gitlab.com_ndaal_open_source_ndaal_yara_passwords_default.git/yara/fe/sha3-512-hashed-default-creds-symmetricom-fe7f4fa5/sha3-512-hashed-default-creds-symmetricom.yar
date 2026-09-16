rule sha3_512_hashed_default_creds_symmetricom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symmetricom."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aa0646454cbb771bc08cbcf46031ff50c3d3a98493e7f0bf01e02a064c9a66f77b48a81a47dfd64d2f7d1229bf89e5b45c0088e9bb8670f61be9ce25944bd8a1"
    $a1="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a2="1770f3ea3c4689349786c2d538bbcbe6c3e6edd081f696042803e8ede7fb4bd5b5db13ef869354c49edcd77ebf36cef7936a7863a67baa3bbf6635d858308445"
    $a3="eb65ed18f38a818be59cfc0c06cc812c1b46ead14d3059b3d0ea8fe388119ae93c30df5ceb94dfd0a2dba10e062066edf65951d4ab734c7f953f95e669d2a0f5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}