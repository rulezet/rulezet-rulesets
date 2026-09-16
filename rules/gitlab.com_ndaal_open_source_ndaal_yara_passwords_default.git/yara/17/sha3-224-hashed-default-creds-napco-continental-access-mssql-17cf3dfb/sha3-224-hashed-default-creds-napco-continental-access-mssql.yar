rule sha3_224_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="68010a8b3b2edd5b007ef3510ce5fe2cdb4d32ee499e3237844e5287"
    $a1="68010a8b3b2edd5b007ef3510ce5fe2cdb4d32ee499e3237844e5287"
    $a2="84240bfc80604d83dbdc446e1f147650c530a0abadf4e522537759e9"
    $a3="68010a8b3b2edd5b007ef3510ce5fe2cdb4d32ee499e3237844e5287"
    $a4="9ef40170e5f7deda01302b182500aa8f97b294bc61fbce159105de46"
    $a5="68010a8b3b2edd5b007ef3510ce5fe2cdb4d32ee499e3237844e5287"
    $a6="68010a8b3b2edd5b007ef3510ce5fe2cdb4d32ee499e3237844e5287"
    $a7="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a8="84240bfc80604d83dbdc446e1f147650c530a0abadf4e522537759e9"
    $a9="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a10="9ef40170e5f7deda01302b182500aa8f97b294bc61fbce159105de46"
    $a11="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}