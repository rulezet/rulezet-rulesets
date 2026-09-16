rule sha512_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d5f92dcae90ec87247840df8a76a195aa1cd0f7fe996b1d79eb6f9da2294338a556b46cfd64e0fe3a00b71952e17a72880b01540485924150fbb5448098e6853"
    $a1="4831e9025d3b3dd22c67747041809111a8be45a305fea7ec919cfb959ad10010d855ae2ba42b9b3156de2a24066522d977a601148002c58610a229264fde82f9"
    $a2="548949b8bfa4ea6042fb2908c25fcd07282ab47b63c055db3b019dc2aa5747ec6ae3754cb1d22d297c78e87b68fad08bfa30737779e1c98d9c8987602c3bd920"
    $a3="548949b8bfa4ea6042fb2908c25fcd07282ab47b63c055db3b019dc2aa5747ec6ae3754cb1d22d297c78e87b68fad08bfa30737779e1c98d9c8987602c3bd920"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}