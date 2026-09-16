rule sha3_224_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f0ee18d48831bf830553f88ec9ad9c8dd3b81a8016620d68f34039a3"
    $a1="f0ee18d48831bf830553f88ec9ad9c8dd3b81a8016620d68f34039a3"
    $a2="93344d3d133e51d0aedc85a0e8910ba726347178db13a8c3a9419577"
    $a3="b88d4fc9071df351fa3841d418d46571fb3918c18ba9b3d5800bc1a5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}