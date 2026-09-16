rule sha3_224_hashed_default_creds_wonderware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wonderware."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d5b2c3d6438811ec4d177746e3312c016a71da5e70180f3bbd7ac68"
    $a1="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a2="8247c391f970009190b3c05269aa85b7a390bb981aa8458ee08bd9dd"
    $a3="3f4438b1bfcd14db5b28aa8ce48ae06535c693ac58b027866af42194"
    $a4="8247c391f970009190b3c05269aa85b7a390bb981aa8458ee08bd9dd"
    $a5="5f0d218895ef0fecf829d5a48e9b29d8d30bd5c223a0451eaec27004"
    $a6="655918ba3de9edd2326de5717f2e295b39316ab3aeb0cd591b03a720"
    $a7="5b8a21522fd9c5943185a7cf664fa54d13874de698c37a7788b9ba08"
    $a8="77d638eba71b3a227d38c49df0c712b5c68a6485acd0d99984fe254d"
    $a9="77d638eba71b3a227d38c49df0c712b5c68a6485acd0d99984fe254d"
    $a10="d0af7a190d65b40c637510e78fa157d81e0429dc78754a8e29dafd46"
    $a11="54769524522a438f1574030fc30218c0c0a1b87ad6de70baf9f84800"
    $a12="9750d6ed0c417ba3bdef3eaebb9c6477ea554ba77086ce0293055d7f"
    $a13="9750d6ed0c417ba3bdef3eaebb9c6477ea554ba77086ce0293055d7f"
    $a14="f082620419b995858d6c70fdb4715f5c4eb24fce8c756f89cd0c7b04"
    $a15="d9a2ed0b27b99f419f6b650dcc5a8e12860a045b8cb110a07a31e8c3"
    $a16="11010051c4f6f966c5b789d7b51d433f27617bb27989688e50820245"
    $a17="11010051c4f6f966c5b789d7b51d433f27617bb27989688e50820245"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}