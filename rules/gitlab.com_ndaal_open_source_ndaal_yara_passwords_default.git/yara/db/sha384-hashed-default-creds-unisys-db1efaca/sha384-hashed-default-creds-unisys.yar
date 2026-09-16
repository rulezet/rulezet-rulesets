rule sha384_hashed_default_creds_unisys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unisys."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eebd241a3d613fd87a4c30402fdd66b0667361380faafcfcb1bcc7e9c7029ca99137d974dd981b45ab947545bda0ec3d"
    $a1="eebd241a3d613fd87a4c30402fdd66b0667361380faafcfcb1bcc7e9c7029ca99137d974dd981b45ab947545bda0ec3d"
    $a2="fdbf2e4eadc2dff798403ceff70a4b86094144d0e4c5e73dcb01cef506bcb573e98c2e2c978660b605e8a78422251a0e"
    $a3="fdbf2e4eadc2dff798403ceff70a4b86094144d0e4c5e73dcb01cef506bcb573e98c2e2c978660b605e8a78422251a0e"
    $a4="e3fc98db1a3da1991bda5ba75b4d0627e1445715d860e6a274e6cea995ada45cf9e619e56a1d6270ab64e82312ca2958"
    $a5="e3fc98db1a3da1991bda5ba75b4d0627e1445715d860e6a274e6cea995ada45cf9e619e56a1d6270ab64e82312ca2958"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}