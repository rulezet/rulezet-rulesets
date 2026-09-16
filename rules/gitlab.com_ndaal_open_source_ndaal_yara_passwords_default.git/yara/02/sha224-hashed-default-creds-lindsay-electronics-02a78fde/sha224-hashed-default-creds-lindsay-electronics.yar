rule sha224_hashed_default_creds_lindsay_electronics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lindsay_electronics."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ecb04afe15a78cd808e1da57e85be94b796731dd14875606e5c808a4"
    $a1="10104dfcce0ff3c3301e0c0cd27abaa31c65dc9d0d2bbee6094ec8f6"
    $a2="ecb04afe15a78cd808e1da57e85be94b796731dd14875606e5c808a4"
    $a3="ecb04afe15a78cd808e1da57e85be94b796731dd14875606e5c808a4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}