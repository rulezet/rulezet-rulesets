rule sha3_384_hashed_default_creds_episd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for episd."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e966fea393df6f2218d5a91c2b7d09ad3a569c43c7221e6895fbbcb4e8a19e4c9e948218ebca2ddacb0c829ba0278c8b"
    $a1="2389b739ae11f7303b554d59da4b58427e4be308a00d9649cbb28901d6a64b709e12a22725afa934d4b3d0e81f281e71"
condition:
    ($a0 and $a1)
}