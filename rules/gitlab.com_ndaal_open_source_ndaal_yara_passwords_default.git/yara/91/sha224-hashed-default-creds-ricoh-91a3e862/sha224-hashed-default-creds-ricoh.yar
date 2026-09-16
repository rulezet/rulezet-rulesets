rule sha224_hashed_default_creds_ricoh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ricoh."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a3="02f382b76ca1ab7aa06ab03345c7712fd5b971fb0c0f2aef98bac9cd"
    $a4="20f6c8d59a3d5399b5c0fa326b0e2f9c3d0e8c39281ce43ab2b77c4f"
    $a5="20f6c8d59a3d5399b5c0fa326b0e2f9c3d0e8c39281ce43ab2b77c4f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}