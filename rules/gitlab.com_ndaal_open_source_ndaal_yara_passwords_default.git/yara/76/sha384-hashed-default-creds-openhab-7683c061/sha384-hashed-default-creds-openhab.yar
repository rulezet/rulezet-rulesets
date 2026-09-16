rule sha384_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cde46cce502798a85bfbc48b007d207decbadcc3ccc567b96d81ad7874050dd2b875d037b1c8aa7ee2826689f6392621"
    $a1="cde46cce502798a85bfbc48b007d207decbadcc3ccc567b96d81ad7874050dd2b875d037b1c8aa7ee2826689f6392621"
    $a2="9a89d9553caaa216e70391c4117fe22e4af4e632f44044cd60bd27d22d5688e638beff602c6c34d4199c616c6db354e8"
    $a3="6f992bc76ea099a077e6d93ce7245a31d8513dae53271544628ea4d3edbb93c1fdee337fc05ba891b5eef45fb4fbb6a9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}