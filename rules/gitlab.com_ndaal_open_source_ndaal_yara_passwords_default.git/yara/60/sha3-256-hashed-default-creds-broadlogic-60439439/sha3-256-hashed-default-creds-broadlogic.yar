rule sha3_256_hashed_default_creds_broadlogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for broadlogic."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cae76c66f907f3a9ad797c25588a373441deb380830161fadc4b1635eb9ce438"
    $a1="cae76c66f907f3a9ad797c25588a373441deb380830161fadc4b1635eb9ce438"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="f6238a3654d68b8148200a053d013ec6c1caf6e12b24679c88d645f80c686bbe"
    $a5="f6238a3654d68b8148200a053d013ec6c1caf6e12b24679c88d645f80c686bbe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}