rule sha3_384_hashed_default_creds_janitza
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for janitza."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cefa764b8c811d5ffc70fbd932bb112bbe2b26985db5117bd3d2af4a4058bae267cffd2375291bab37951225a2f6a2d1"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="cefa764b8c811d5ffc70fbd932bb112bbe2b26985db5117bd3d2af4a4058bae267cffd2375291bab37951225a2f6a2d1"
    $a3="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a4="a1156686aacd668f3e52b8b83e20176ee6a5c7ec9939f05b0ca83dc24ae9693164f1d33454e3961f27c03fc4d4a85f8d"
    $a5="f08e5149e33ef3fa24c4c2e771aafc9bd82de40271c35df683174533e68fed7475f9f043db6453b974aa90e7d55d4ce2"
    $a6="cefa764b8c811d5ffc70fbd932bb112bbe2b26985db5117bd3d2af4a4058bae267cffd2375291bab37951225a2f6a2d1"
    $a7="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}