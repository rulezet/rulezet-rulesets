rule sha1_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="44f4f26e7ac9a4ef1ec6e87df92e1dcf27bab738"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="536c0b339345616c1b33caf454454d8b8a190d6c"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="cdb0e76c1a69873cbdcdbe0a142d56c023dc9f22"
    $a7="8dca46428d005a2f4c2e039fb250964d6139a8b2"
    $a8="91b1a5369590bab100066e1c83e2317a1adb2a76"
    $a9="91b1a5369590bab100066e1c83e2317a1adb2a76"
    $a10="cdb0e76c1a69873cbdcdbe0a142d56c023dc9f22"
    $a11="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a12="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a13="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a14="cdb0e76c1a69873cbdcdbe0a142d56c023dc9f22"
    $a15="536c0b339345616c1b33caf454454d8b8a190d6c"
    $a16="536c0b339345616c1b33caf454454d8b8a190d6c"
    $a17="536c0b339345616c1b33caf454454d8b8a190d6c"
    $a18="536c0b339345616c1b33caf454454d8b8a190d6c"
    $a19="fc39b18f287d8bbfaceae020f4a4eb32ac5c1e70"
    $a20="536c0b339345616c1b33caf454454d8b8a190d6c"
    $a21="91b1a5369590bab100066e1c83e2317a1adb2a76"
    $a22="f35249adca11603f3229272cfe3f6c95a1ae08ff"
    $a23="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}