rule sha3_384_hashed_default_creds_beck_ipc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for beck_ipc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1c9a5f6dc335d3fbb11047e849dec8c2e87f0fa64db018f689c7e192c18fc50be943d32e196a1917adbb342e9239ff14"
    $a1="1c9a5f6dc335d3fbb11047e849dec8c2e87f0fa64db018f689c7e192c18fc50be943d32e196a1917adbb342e9239ff14"
condition:
    ($a0 and $a1)
}