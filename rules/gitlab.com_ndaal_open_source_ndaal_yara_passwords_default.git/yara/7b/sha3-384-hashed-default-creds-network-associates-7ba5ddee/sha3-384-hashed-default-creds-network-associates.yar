rule sha3_384_hashed_default_creds_network_associates
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for network_associates."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a130ee831b24f499c4aa3a99a389e6c5e6eebe767d408591235c4a9a2e1c24f395056c3e46de95d9a1fb869492c4d5ca"
    $a1="8501e5a3fed811600ebc2f02a626472f6a93adba63532101dfe050e2fed586529dfa00d36054024b84825e4759a2235c"
    $a2="45d359ed93db161812ecaa3524e268d34204689d8a91e02b8bc406daae708652ca13362b952c67d75d136f845de6a34f"
    $a3="aa5d8f5685d4f1fc9526a988e5c5a7dab2af1408c20fafe8ded016cbf66434f82610f1ec07531fa817e40727bfef2dfd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}