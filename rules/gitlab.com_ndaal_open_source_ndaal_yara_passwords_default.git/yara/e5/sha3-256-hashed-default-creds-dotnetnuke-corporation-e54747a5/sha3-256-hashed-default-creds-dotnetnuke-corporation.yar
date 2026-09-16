rule sha3_256_hashed_default_creds_dotnetnuke_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dotnetnuke_corporation."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d2eaf15b42968a73155fa0d24cd4c95040b9c00456c56a0ce9fc59f384d34586"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="52c775b5506476a324efb4f580bc568d0cf4338f58d0ea44dc50cf03344cc532"
    $a3="cd6eabc83530c226c655cb021ea0d14f5e5675059796de05ac6cd7ea26bebaa5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}