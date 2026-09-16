rule sha3_512_hashed_default_creds_lgic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lgic."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="63fac862d7b18721e6de9e64b9b24ad54d4c84b4c7f5f42b75ae1aa005404b8df546e6344d984303bc8d6ce15cb2f8bd4662cc0a496e1ddd4e439c08085e6930"
    $a1="63fac862d7b18721e6de9e64b9b24ad54d4c84b4c7f5f42b75ae1aa005404b8df546e6344d984303bc8d6ce15cb2f8bd4662cc0a496e1ddd4e439c08085e6930"
condition:
    ($a0 and $a1)
}