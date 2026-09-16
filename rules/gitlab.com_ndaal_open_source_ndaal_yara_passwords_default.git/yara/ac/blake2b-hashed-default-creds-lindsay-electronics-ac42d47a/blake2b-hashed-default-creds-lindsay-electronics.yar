rule blake2b_hashed_default_creds_lindsay_electronics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lindsay_electronics."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c46a96643e9514b43973b17020452c4b1978edfbf7329d9d691cd4383ad6fda83cb46354f80bf8a964364468b5ac8d9ea8a16300f8b7124bd7a8241a667e73bb"
    $a1="2fcc7f0fb746f5731e2986d3c801ba2f8750cf8ce6c0c94530122dd2ec503b798bc4d1bebec41040242b9b349ab0ac34f2f5ac0320e83b64dffcddf1e97efad4"
    $a2="c46a96643e9514b43973b17020452c4b1978edfbf7329d9d691cd4383ad6fda83cb46354f80bf8a964364468b5ac8d9ea8a16300f8b7124bd7a8241a667e73bb"
    $a3="c46a96643e9514b43973b17020452c4b1978edfbf7329d9d691cd4383ad6fda83cb46354f80bf8a964364468b5ac8d9ea8a16300f8b7124bd7a8241a667e73bb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}