rule sha3_384_hashed_default_creds_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for brother."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8515c138c59d8d72b3d9ec1bb64c0ee8f1d8e270d29c1eb632b0ae048661bf0121c24c7749166760a022f8c2d48fab62"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="8515c138c59d8d72b3d9ec1bb64c0ee8f1d8e270d29c1eb632b0ae048661bf0121c24c7749166760a022f8c2d48fab62"
    $a3="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}