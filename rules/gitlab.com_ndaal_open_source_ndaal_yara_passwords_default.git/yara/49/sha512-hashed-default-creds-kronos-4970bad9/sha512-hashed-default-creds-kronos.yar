rule sha512_hashed_default_creds_kronos
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kronos."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43b6706d02941af0d28ced9d9bf5592f84bd9677233524dc7567a99c7d34259cf238149b60711023534cb66a1097c4de0e72f29c9d15d4568acd7068c3f2bcb3"
    $a1="075623ab889d3ee9cc33a688b403105564abfbffbd9aecdaaeada5e3284f7e0496462f3acaa3e80056eda90bb5c9e548a958eeea796d5411f8acf8b9012909c2"
condition:
    ($a0 and $a1)
}