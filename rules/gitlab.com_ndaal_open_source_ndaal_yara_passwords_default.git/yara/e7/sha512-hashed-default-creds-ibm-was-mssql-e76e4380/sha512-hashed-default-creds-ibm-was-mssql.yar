rule sha512_hashed_default_creds_ibm_was_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_was_mssql."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="11b6b4d3f1a12a0a96487520aee711b0a74413caebcbdfb0476f0939b7f7dcf424fd6e77dbb65ff387f00573a43f653af38fa0112c4d3bf45f3c55fee888707f"
    $a1="11b6b4d3f1a12a0a96487520aee711b0a74413caebcbdfb0476f0939b7f7dcf424fd6e77dbb65ff387f00573a43f653af38fa0112c4d3bf45f3c55fee888707f"
condition:
    ($a0 and $a1)
}