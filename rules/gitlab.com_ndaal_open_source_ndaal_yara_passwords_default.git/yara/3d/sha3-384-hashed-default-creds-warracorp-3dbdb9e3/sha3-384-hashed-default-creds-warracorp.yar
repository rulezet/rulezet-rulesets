rule sha3_384_hashed_default_creds_warracorp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for warracorp."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="880e8961beb1ef919ec0a96cf44c1b23556c899a8428aa46a26c765db36c488d6468d1776839e7857705198871018836"
    $a1="880e8961beb1ef919ec0a96cf44c1b23556c899a8428aa46a26c765db36c488d6468d1776839e7857705198871018836"
condition:
    ($a0 and $a1)
}