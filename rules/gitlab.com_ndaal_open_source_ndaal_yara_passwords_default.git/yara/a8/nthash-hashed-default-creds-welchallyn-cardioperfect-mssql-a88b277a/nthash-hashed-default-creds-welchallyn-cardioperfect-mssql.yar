rule nthash_hashed_default_creds_welchallyn_cardioperfect_mssql
{
    meta:
        id = "73jfIMmX10EN4vRlrxjnsD"
        fingerprint = "36c4f0d229e9e7f17c3a86fafc05c0a2612f1f79563584d4aabe5838589c6c22"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for welchallyn_cardioperfect_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ff6ff6cbce873badacc7b968d10bc7eb"
    $a1="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1)
}