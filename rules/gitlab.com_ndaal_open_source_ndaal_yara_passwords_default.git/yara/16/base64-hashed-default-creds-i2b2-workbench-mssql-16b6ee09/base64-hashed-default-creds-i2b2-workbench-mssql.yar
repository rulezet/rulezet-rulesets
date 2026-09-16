rule base64_hashed_default_creds_i2b2_workbench_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for i2b2_workbench_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="STJiMmRlbW9kYXRhMg=="
    $a1="aTJiMmRlbW9kYXRhMg=="
    $a2="STJiMmRlbW9kYXRh"
    $a3="aTJiMmRlbW9kYXRh"
    $a4="STJiMmhpdmU="
    $a5="aTJiMmhpdmU="
    $a6="STJiMm1ldGFkYXRhMg=="
    $a7="aTJiMm1ldGFkYXRhMg=="
    $a8="STJiMm1ldGFkYXRh"
    $a9="aTJiMm1ldGFkYXRh"
    $a10="STJiMndvcmtkYXRhMg=="
    $a11="aTJiMndvcmtkYXRhMg=="
    $a12="STJiMndvcmtkYXRh"
    $a13="aTJiMndvcmtkYXRh"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}