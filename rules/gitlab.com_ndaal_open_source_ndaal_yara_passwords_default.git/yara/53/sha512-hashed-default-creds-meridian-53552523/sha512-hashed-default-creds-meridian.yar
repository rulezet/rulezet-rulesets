rule sha512_hashed_default_creds_meridian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for meridian."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8309dd7c52675caaf669868c10bb5616d28daec1e47001277118e7832a22fa7e624a497edcae4a8eb0c74b9f2f64882ce7978492b99cc4975fccece756c4712c"
    $a1="b719607226d34094f53b043491697d98875096ff36bab4aab89da12850ac56195b183a0170976efbe29a6a4ddcc1f114b8f00154933ba6f766d82e5a63624eb4"
condition:
    ($a0 and $a1)
}