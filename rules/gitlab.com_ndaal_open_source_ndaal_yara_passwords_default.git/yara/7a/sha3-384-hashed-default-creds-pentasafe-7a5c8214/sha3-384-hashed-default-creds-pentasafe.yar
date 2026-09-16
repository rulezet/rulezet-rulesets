rule sha3_384_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="289b191ef2cee28776b6f53c49602880724c18fb0e5c054f172704d9a34bd066f06e8cd672f256c2bd875b432be0f011"
    $a1="afee720e06b2a5afd21a8b88287283a920685cbb6969c1d18c47283ba95b6c6d66e3c1d7ad6535205c825d0e0e757442"
condition:
    ($a0 and $a1)
}