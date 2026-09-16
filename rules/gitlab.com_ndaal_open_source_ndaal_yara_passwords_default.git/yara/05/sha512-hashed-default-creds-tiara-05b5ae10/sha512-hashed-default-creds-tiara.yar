rule sha512_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="98c2f891db63d6f2c0b925ec72d005b59ea25a8817da9387bd16890666180bd7dc9cf818374b949ea33ccbec2d51271fa9a6a8613d5a0b9652d139781f13b59b"
    $a1="25fbbee6fcd8bf82005c2bd26de781c81060d780cfc4629639634e5ec647c71a7ed4094d51b387b1d82135aac539042b35a047ed0955d3ce4a59e262e9c0f3b2"
condition:
    ($a0 and $a1)
}