rule sha384_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b7e865b61d14ade6769055a3d265f370237790dd8b1f9f6a5f18fe142e539c48b4700f8ceec2c5b3988b232722d1053c"
    $a1="86bbe6ff9f2c4d98744746c5fcafec418c49a6022551dc86aafd1a2fc55b390b4f4464fc872d28c58a2ecaeb6f7acb8e"
    $a2="b7e865b61d14ade6769055a3d265f370237790dd8b1f9f6a5f18fe142e539c48b4700f8ceec2c5b3988b232722d1053c"
    $a3="dac3eb87aa375e3108383ea7efdaf95e662c44312cb0d5d9f3d0a4ee26c53a9b41126c9e510523edf29ab1635c74fe71"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}