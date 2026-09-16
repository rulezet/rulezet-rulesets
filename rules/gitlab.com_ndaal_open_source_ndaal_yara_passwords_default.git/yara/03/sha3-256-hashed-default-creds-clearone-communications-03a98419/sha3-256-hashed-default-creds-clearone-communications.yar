rule sha3_256_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a32f6c38af28e930ea85aa730dd0c0d87f7885cb3f9db5c7882045c54ef6274f"
    $a1="4ec81bd44262c70330bd50fefa7189352c0c0e95025a15148be39c1484b592b9"
    $a2="1682c530a80b82e27c31b40bc8187e0f727d461d4587bdafe9456ea7d09a073e"
    $a3="d7d6e1b9955c2c48883ffa8763103f517d560769acadc438b15b3ae664cbe899"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}