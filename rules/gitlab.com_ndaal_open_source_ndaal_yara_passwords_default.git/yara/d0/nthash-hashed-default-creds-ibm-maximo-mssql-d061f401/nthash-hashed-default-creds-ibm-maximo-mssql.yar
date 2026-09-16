rule nthash_hashed_default_creds_ibm_maximo_mssql
{
    meta:
        id = "2ajESRR3DqsL6tC4ygMRPr"
        fingerprint = "9af38857866a317d52cc38a5a982e3c976e97a57ca43f51db7a43a72f183aafc"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_maximo_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4337cd153fadef086e20f927bb9a3fd7"
    $a1="4337cd153fadef086e20f927bb9a3fd7"
    $a2="fba35e87681a03de4a1e8aacdbda44e5"
    $a3="fba35e87681a03de4a1e8aacdbda44e5"
    $a4="ab477717735e04d40339a55ea31fb8d7"
    $a5="ab477717735e04d40339a55ea31fb8d7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}