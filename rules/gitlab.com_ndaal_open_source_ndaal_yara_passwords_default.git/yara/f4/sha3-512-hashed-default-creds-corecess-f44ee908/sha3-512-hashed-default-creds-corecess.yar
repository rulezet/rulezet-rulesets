rule sha3_512_hashed_default_creds_corecess
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for corecess."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7cce71855465925838350c2b966641fb81e561e167bb14c4012fe4d87b30f600be461a74c5f317cd62bb0ac5c96a8f082ac81563d0edfd378f9b989a3ac9b06a"
    $a1="7cce71855465925838350c2b966641fb81e561e167bb14c4012fe4d87b30f600be461a74c5f317cd62bb0ac5c96a8f082ac81563d0edfd378f9b989a3ac9b06a"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}