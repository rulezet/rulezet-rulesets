rule sha3_512_hashed_default_creds_everfocus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for everfocus."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="eb65ed18f38a818be59cfc0c06cc812c1b46ead14d3059b3d0ea8fe388119ae93c30df5ceb94dfd0a2dba10e062066edf65951d4ab734c7f953f95e669d2a0f5"
    $a3="eb65ed18f38a818be59cfc0c06cc812c1b46ead14d3059b3d0ea8fe388119ae93c30df5ceb94dfd0a2dba10e062066edf65951d4ab734c7f953f95e669d2a0f5"
    $a4="d7fe5e2e1ab20da6becbbbd478b7ef4d3d28fbda00f8f66a7881e2794d413b5e5bea54ee5667f7136554eb35115d91d7a8c830b9895a383a13ea4874d8dad25f"
    $a5="d7fe5e2e1ab20da6becbbbd478b7ef4d3d28fbda00f8f66a7881e2794d413b5e5bea54ee5667f7136554eb35115d91d7a8c830b9895a383a13ea4874d8dad25f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}