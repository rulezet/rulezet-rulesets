rule sha512_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21c66014a21008e9addd9e93d4ae2a8e30f8553399745360717b675f3f8a8ded0ec0bc17b6572695658d6d0fee8c83a8b83ebc688696b4cb9edf0bb51dbc4491"
    $a1="401ea91dcbd27df1131a68e94457b637be81684d124798b89af3fc36bfb06651d051c970bc28f66abe58045f92c7b4301d52306c47914a646eb71c04a2a3438a"
condition:
    ($a0 and $a1)
}