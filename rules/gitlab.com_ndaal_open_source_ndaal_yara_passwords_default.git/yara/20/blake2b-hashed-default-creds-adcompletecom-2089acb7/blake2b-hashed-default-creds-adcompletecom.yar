rule blake2b_hashed_default_creds_adcompletecom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adcompletecom."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d21043cd59511c4762c11ea171e5d0595e65129efa7f997958976d4047a0824aba6505daeb5a480af2f133aeb8beff62775a96762319e28266e9a39e7999ede"
    $a1="1d21043cd59511c4762c11ea171e5d0595e65129efa7f997958976d4047a0824aba6505daeb5a480af2f133aeb8beff62775a96762319e28266e9a39e7999ede"
condition:
    ($a0 and $a1)
}