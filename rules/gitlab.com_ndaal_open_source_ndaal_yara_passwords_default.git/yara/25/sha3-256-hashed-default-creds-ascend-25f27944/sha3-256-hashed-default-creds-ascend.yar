rule sha3_256_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="91580e467eda1432da3ac8b3e2541033fa0c733e544a82024dabf260dc326cf1"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="a214f7312073b63bf1c183534e979b18533771ab290e105043b898942702a995"
    $a3="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a4="9f9b41032ecfcb70a6060c45f72cfe28c7a982a75e1dcca4f02d82bdf58bfd3b"
    $a5="057d1b930b9c8e962bf34656a2c010888ae6a2a5fc4de074ecc8cb3bf4782685"
    $a6="ca177780df436f74a06ea281c897a680fb5c59033451d73faa0e65ec25da4ad9"
    $a7="ecadc4b42ff468b63d113a1ff868aa2d8c4566bfc8e41c6c0b1197f0cc86cf0f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}