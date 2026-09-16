rule sha3_512_hashed_default_creds_fortinet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fortinet."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="2f01dac6a2ff602460f44a8337a4910c6b39ec4aa315245029243c73a51544c0779c5e1b3e9239bdff4d8decf2747dc161e9f30edfaa1e0d9f4ef9d231d020a9"
    $a2="0d8ff3d321531d78f92467b717c4f061235ea0a96ad710639d03970c04c43adb0c4ce394594ccdca9fc16d86c057f28858393fea1955e7a26c8bf1462098e6e4"
    $a3="2f01dac6a2ff602460f44a8337a4910c6b39ec4aa315245029243c73a51544c0779c5e1b3e9239bdff4d8decf2747dc161e9f30edfaa1e0d9f4ef9d231d020a9"
    $a4="a89a5c422f0abb27bddbd6c81c8723c8ec2c415f57dc249daf80e857d5ecd9191a9d744ee2300f0c3cbe8d9c05501540d7eba027722e9a6c9d25d6e79338dd8c"
    $a5="2f01dac6a2ff602460f44a8337a4910c6b39ec4aa315245029243c73a51544c0779c5e1b3e9239bdff4d8decf2747dc161e9f30edfaa1e0d9f4ef9d231d020a9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}