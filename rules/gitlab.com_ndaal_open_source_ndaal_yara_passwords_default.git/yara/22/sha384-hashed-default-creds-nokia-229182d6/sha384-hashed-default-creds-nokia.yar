rule sha384_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fde45e7a0492240962f1c83ac2e27af3023758079177620e47d83669c955aa4a1b535b7128f810b46eb7fc2cead3e6c6"
    $a1="fde45e7a0492240962f1c83ac2e27af3023758079177620e47d83669c955aa4a1b535b7128f810b46eb7fc2cead3e6c6"
    $a2="defd7b8c342efc74c397228ba9c2090c7565453d472cad2434cd4ac29e16d28655015c65f1e224e378e5887f71a8ddbb"
    $a3="defd7b8c342efc74c397228ba9c2090c7565453d472cad2434cd4ac29e16d28655015c65f1e224e378e5887f71a8ddbb"
    $a4="dccfe25e8c0d8b5b355fe1e715f466b3e7027be30acbf965f4e6160045ea11a6d871190306f00fbabd09931a2a0bea2e"
    $a5="dccfe25e8c0d8b5b355fe1e715f466b3e7027be30acbf965f4e6160045ea11a6d871190306f00fbabd09931a2a0bea2e"
    $a6="0fa76955abfa9dafd83facca8343a92aa09497f98101086611b0bfa95dbc0dcc661d62e9568a5a032ba81960f3e55d4a"
    $a7="ff05f65a7ba581f9cc95d243128fa47f3fa3c34c8d4efe6761c62a8a4f083e90081722a2fab656b335887a24535b1550"
    $a8="2bc130303bb7c1ed0c32351d922e0759add2cb648f7e25ea0b1fb3aa48403117f7f5e1d8faa5c7fd1aae93b56038b647"
    $a9="ff05f65a7ba581f9cc95d243128fa47f3fa3c34c8d4efe6761c62a8a4f083e90081722a2fab656b335887a24535b1550"
    $a10="82cd45637b6e37ef02482a4d769c1bc1caabc0201a9236f739c285053549ca80d0ef2d554abf072558330627d36b44b4"
    $a11="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a12="e1df526616174e93218657e00cf11841173920b8bb984ab531b2a0c5ec111e342e1bce34a95a905b80c93916f9fc0da2"
    $a13="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a14="0fa76955abfa9dafd83facca8343a92aa09497f98101086611b0bfa95dbc0dcc661d62e9568a5a032ba81960f3e55d4a"
    $a15="873574cfb5ba53f2cad1e4673f59b6764d52bf83a2b3a4f81a7aabbc5c3a2671640731ae078d1aad2c3838b055b23ab5"
    $a16="118cafcc919f7e0212f0ce0bd057a0f5452f501ae2f8c5663c60164286dcad1c87723293e4314f644d9ee53a7d437119"
    $a17="118cafcc919f7e0212f0ce0bd057a0f5452f501ae2f8c5663c60164286dcad1c87723293e4314f644d9ee53a7d437119"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}