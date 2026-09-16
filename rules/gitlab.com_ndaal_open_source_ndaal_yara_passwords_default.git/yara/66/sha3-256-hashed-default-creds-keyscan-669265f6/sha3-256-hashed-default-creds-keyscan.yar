rule sha3_256_hashed_default_creds_keyscan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for keyscan."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8e1fa77089b1b0241df46ef0530c799e9c2f3a0a6740ef64924a21aad30ace5f"
    $a1="0ad9c4345af3932fedd4b324b50bdb93c0e102f68a1298de0ad2d0deabf15144"
condition:
    ($a0 and $a1)
}