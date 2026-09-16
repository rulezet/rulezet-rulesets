rule sha3_384_hashed_default_creds_team_xodus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for team_xodus."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bc9d433da860db1ae55d7dba03251945b66fad207ff41ef84453112bfb46d30271ca96dfd9621df0f5b77018fc7fc87c"
    $a1="bc9d433da860db1ae55d7dba03251945b66fad207ff41ef84453112bfb46d30271ca96dfd9621df0f5b77018fc7fc87c"
condition:
    ($a0 and $a1)
}