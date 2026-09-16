rule sha3_256_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9896588693639f683fb7fd8122e993fff0b5a229f76787049530e53d7b566a59"
    $a1="9896588693639f683fb7fd8122e993fff0b5a229f76787049530e53d7b566a59"
    $a2="ee43538c914ae6eba6920eef5131535efa6da76ed7d914e637013d6cb47ad563"
    $a3="ee43538c914ae6eba6920eef5131535efa6da76ed7d914e637013d6cb47ad563"
    $a4="1e8f8d126fca81b63ed20e4a831e5a0453ace4c9042efea274329fd740bfb881"
    $a5="1e8f8d126fca81b63ed20e4a831e5a0453ace4c9042efea274329fd740bfb881"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}