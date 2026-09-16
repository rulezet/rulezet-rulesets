rule sha3_224_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="191a452050220815ecf53b385b21927c7ce4987503c003f50370d499"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="f9cd59184b9e4f57fad4ac82db27cd444dbdbc09df070aa86441f0fe"
    $a3="e9ced4a9908bd9dd07a8020d01997973785b6e455a90e1249a7abda7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}