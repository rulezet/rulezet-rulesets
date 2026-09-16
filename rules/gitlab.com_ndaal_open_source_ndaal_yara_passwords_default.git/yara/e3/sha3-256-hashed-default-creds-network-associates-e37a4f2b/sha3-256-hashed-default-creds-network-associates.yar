rule sha3_256_hashed_default_creds_network_associates
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for network_associates."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6f9c367574f0c9861cfc13a1389af7da4e47cd00a86be9ed29831e785f6f4ca9"
    $a1="bdf5c5032f5ea6152c984e035eb40c809440d77c4a89f1e00496e5309641137b"
    $a2="fc9d4fe67296f4bf92b64708e437ac2072657fa417d3f9c771bcd3bcc5f67e17"
    $a3="cad5c7cd2f8efbc78365abcfec9e4ed1e8f86fca0fec6b5049065f338ab2ff38"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}