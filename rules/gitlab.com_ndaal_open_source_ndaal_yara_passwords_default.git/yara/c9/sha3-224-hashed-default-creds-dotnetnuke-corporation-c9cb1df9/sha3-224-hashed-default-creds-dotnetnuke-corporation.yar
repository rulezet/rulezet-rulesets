rule sha3_224_hashed_default_creds_dotnetnuke_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dotnetnuke_corporation."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a055b5ab54022db10e15626f800150723eda262a61cfc0be59f2376"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="7bf3bc56cef319a06b0c3916ee4f27712e4bf172abd4be1a3be61e67"
    $a3="db5e30a47322c761740480c3247b59f6bf662982e2d03c72de2c9b83"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}