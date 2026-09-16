rule sha3_256_hashed_default_creds_symbol
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symbol."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="afdd4a73b7219632c5e045c426ad106d1564c96ecfe9299cdcb9d5af0f7e1ed2"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="c7e54715454ed8169f67e800a58be511c2f8c0236e088e895d393c81c944e2d7"
    $a3="c7e54715454ed8169f67e800a58be511c2f8c0236e088e895d393c81c944e2d7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}