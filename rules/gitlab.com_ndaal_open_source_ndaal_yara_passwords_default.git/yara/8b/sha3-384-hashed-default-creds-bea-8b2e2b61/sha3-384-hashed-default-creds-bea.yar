rule sha3_384_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a1="85329d087922707acda4d9039e6e2fb6fa648aa587412db830d10e861754f6212ba96fa16cadcc19e038629409ee90a1"
    $a2="e93d6fd44e5a6e57fc6083328ed79695f48fec43cab2e5b2d797084fba8ab17ddcceba629dbbf75c6fef680193fb4c40"
    $a3="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
    $a4="c54f0043b456e5b813e530055fc8e47745146b511db337338eabb6be7863f31f1142e389d853f8d476eef73703ba1209"
    $a5="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}