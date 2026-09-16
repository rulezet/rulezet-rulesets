rule sha3_512_hashed_default_creds_atl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atl."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99b5c68e11408006b41ff5f0c8d17a62d4e394363bc80bdd255180e6a359fc4b84670a7109b21d4b7886a2e41e6b138284811f1c3623b0ffcb89c511c2bb9270"
    $a1="f1343b3626745557e40e3014d28a07766a31c925778a9509b048d518429b72973d8be7ff9ab3e78597885f321c5f4786e2a61b51436d868479e40cd7daa91242"
    $a2="d760688da522b4dc3350e6fb68961b0934f911c7d0ff337438cabf4608789ba94ce70b6601d7e08a279ef088716c4b1913b984513fea4c557d404d0598d4f2f1"
    $a3="eb65ed18f38a818be59cfc0c06cc812c1b46ead14d3059b3d0ea8fe388119ae93c30df5ceb94dfd0a2dba10e062066edf65951d4ab734c7f953f95e669d2a0f5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}