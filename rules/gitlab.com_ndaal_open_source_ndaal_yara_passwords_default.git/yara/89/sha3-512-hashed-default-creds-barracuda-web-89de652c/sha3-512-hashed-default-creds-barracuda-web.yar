rule sha3_512_hashed_default_creds_barracuda_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barracuda_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="8905282d0a973b11bf2ddc0cc54eb5869562283229db5ffb767a164d0e6b0d62bb0d2a7220c401ea4a653ac826b4e06f4a8fc17c574f17ab91d8418df22b9b06"
    $a3="8905282d0a973b11bf2ddc0cc54eb5869562283229db5ffb767a164d0e6b0d62bb0d2a7220c401ea4a653ac826b4e06f4a8fc17c574f17ab91d8418df22b9b06"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}