rule sha3_256_hashed_default_creds_barracuda
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barracuda."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="6be64fd0ca0a77e32a3d8a08ac9f3ee78488518d6e474ac50442aa2f64f31e8c"
    $a3="6be64fd0ca0a77e32a3d8a08ac9f3ee78488518d6e474ac50442aa2f64f31e8c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}