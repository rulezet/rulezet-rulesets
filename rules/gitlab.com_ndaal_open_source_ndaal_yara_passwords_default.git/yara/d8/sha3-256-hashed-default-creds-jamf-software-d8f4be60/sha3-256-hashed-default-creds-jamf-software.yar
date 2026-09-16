rule sha3_256_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9cf7d7e93d287dedaf38c841e555c826c15e633e020d5b283a4f4a6d171ce534"
    $a1="8e067376dca90310c9a248bd1ed572d4fb5269703eb19ef290328d86c1d4c0bb"
condition:
    ($a0 and $a1)
}