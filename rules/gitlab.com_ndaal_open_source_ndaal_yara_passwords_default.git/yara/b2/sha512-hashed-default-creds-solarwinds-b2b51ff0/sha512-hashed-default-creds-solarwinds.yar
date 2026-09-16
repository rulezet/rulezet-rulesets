rule sha512_hashed_default_creds_solarwinds
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for solarwinds."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a60738163e04c9afb88a9503a99b9bd5d8a5aec0c7c9ae2ce543bb34313e28bcd90cab7aef4c60ddfc4201c66925b9427665a3b8885a86887849bb6a0c3e79f5"
    $a1="1b1aac4e26b21a901b2a450766a6036d4e707e27155bbf45f0743349cacf7f733bef45cadb2680709f22579faf0618b6f4ac377858b40310f53853d8c1cc4809"
    $a2="dba5bb06a565c761555fb871700804ce7a296226828be1152361117b336ad237ca1ceaf5917e718882f20ef1d0b094c33aa31518e964c555d3cb80f1a0a93170"
    $a3="dba5bb06a565c761555fb871700804ce7a296226828be1152361117b336ad237ca1ceaf5917e718882f20ef1d0b094c33aa31518e964c555d3cb80f1a0a93170"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}