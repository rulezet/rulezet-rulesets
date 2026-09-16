rule blake2b_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4750d18fe9450fed836299927b5501d108a3eb413826946f50db42fd06b2845854d7ad19063dd9f8cd544119e7fe6fecfc2bfec593698066c1c91749da467c9b"
    $a1="0a108d5bcebe7fbce3ebe0ed5a1cf0066b0334afa9dbbfad9786ace5c39fc991f1cd60276777ef57d33ca994dc9e28c78274e17d5a1aaa89d01e5c5c808cd37a"
condition:
    ($a0 and $a1)
}