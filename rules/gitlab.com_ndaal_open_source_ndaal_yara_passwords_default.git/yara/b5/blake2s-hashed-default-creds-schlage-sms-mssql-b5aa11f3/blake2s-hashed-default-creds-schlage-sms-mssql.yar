rule blake2s_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4247843133c0643f01f0994852c52ac076535a4b17dd62ad6450a3d6a80f63a1"
    $a1="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
    $a2="4247843133c0643f01f0994852c52ac076535a4b17dd62ad6450a3d6a80f63a1"
    $a3="2a40a2d445c601b9ef86c2d92fd47b50b83c820a1776e4a745feaf941528119b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}