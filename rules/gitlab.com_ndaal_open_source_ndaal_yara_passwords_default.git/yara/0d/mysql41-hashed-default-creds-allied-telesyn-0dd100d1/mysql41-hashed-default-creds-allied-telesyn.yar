rule mysql41_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*7D2ABFF56C15D67445082FBB4ACD2DCD26C0ED57"
    $a1="*7D2ABFF56C15D67445082FBB4ACD2DCD26C0ED57"
    $a2="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a3="*7D2ABFF56C15D67445082FBB4ACD2DCD26C0ED57"
    $a4="*67CCB3E4C7D082F59E21B16E36C6655A938EBABE"
    $a5="*6695524259F1EEA28BDD985FC5235873DBF015E4"
    $a6="*67CCB3E4C7D082F59E21B16E36C6655A938EBABE"
    $a7="*7D2ABFF56C15D67445082FBB4ACD2DCD26C0ED57"
    $a8="*D28AA394BB8D942030AAA56A45C3EC7CD3012295"
    $a9="*D28AA394BB8D942030AAA56A45C3EC7CD3012295"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}