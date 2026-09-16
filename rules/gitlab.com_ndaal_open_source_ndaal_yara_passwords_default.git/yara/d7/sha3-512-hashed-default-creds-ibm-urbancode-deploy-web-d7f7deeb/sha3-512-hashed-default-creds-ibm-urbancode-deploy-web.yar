rule sha3_512_hashed_default_creds_ibm_urbancode_deploy_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_urbancode_deploy_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="dffda7d8f2fad83ff5e7410f2509e04113f2b4e3adf7d84e096002c373af21eeb38163315dafa3b5e227499544bc7af707248d265e26b3a079e163debaec718f"
    $a3="dffda7d8f2fad83ff5e7410f2509e04113f2b4e3adf7d84e096002c373af21eeb38163315dafa3b5e227499544bc7af707248d265e26b3a079e163debaec718f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}