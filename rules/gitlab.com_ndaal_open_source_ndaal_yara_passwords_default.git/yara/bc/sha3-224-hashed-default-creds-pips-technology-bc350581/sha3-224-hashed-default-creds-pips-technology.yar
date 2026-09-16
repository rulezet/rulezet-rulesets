rule sha3_224_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="457f6b86fb631acb87af20e0344cedbee5be2fdc9badd1d62c910a08"
    $a1="457f6b86fb631acb87af20e0344cedbee5be2fdc9badd1d62c910a08"
    $a2="f6eb28c154d3d8627fe393b04f5c0d3c25827fe6a7a72eb8ec7c4672"
    $a3="f6eb28c154d3d8627fe393b04f5c0d3c25827fe6a7a72eb8ec7c4672"
    $a4="5a74511105b388984bf453c7cf6cf0da18fdc2179ba250c8479546f1"
    $a5="5a74511105b388984bf453c7cf6cf0da18fdc2179ba250c8479546f1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}