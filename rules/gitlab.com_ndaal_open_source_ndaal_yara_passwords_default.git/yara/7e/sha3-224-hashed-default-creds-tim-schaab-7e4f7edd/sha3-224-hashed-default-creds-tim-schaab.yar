rule sha3_224_hashed_default_creds_tim_schaab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tim_schaab."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="796a752e3ba6302e6e5bf7c2e217de4782cad48b23373c1439064aa7"
    $a1="dc51e79a1c1bcf77dcafe187a816f41696607b1cc7d0229539f6e387"
condition:
    ($a0 and $a1)
}