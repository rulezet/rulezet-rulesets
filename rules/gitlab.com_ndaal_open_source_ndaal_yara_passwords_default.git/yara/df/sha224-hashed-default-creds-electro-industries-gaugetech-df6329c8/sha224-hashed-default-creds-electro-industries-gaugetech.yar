rule sha224_hashed_default_creds_electro_industries_gaugetech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for electro_industries_gaugetech."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2ce11767207a153185b411fb5cd2d3cee0c35a954aa59a1511beed1d"
    $a1="2ce11767207a153185b411fb5cd2d3cee0c35a954aa59a1511beed1d"
    $a2="bdb2d243317c5344ba713faed6e78504f7d9e0582ae3c9a1ccd34d22"
    $a3="b6796d4729809cd0ec043d51490560e0f99a5d11366051aa1b10c5e5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}