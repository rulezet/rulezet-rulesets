rule blake2s_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a8b6d185970be2a73a51fdbcd1784cca22c4572ec4545e3a1e7586bb8002ae86"
    $a1="a8b6d185970be2a73a51fdbcd1784cca22c4572ec4545e3a1e7586bb8002ae86"
    $a2="663df51d8382d92d97be9678b5304abf1a7fba9aa7d0347d87cf7e68f8ada4a6"
    $a3="663df51d8382d92d97be9678b5304abf1a7fba9aa7d0347d87cf7e68f8ada4a6"
    $a4="abaa5bb05208fd64301e73fc3242743bb6f93bdb9250f8a50068c994eb740636"
    $a5="abaa5bb05208fd64301e73fc3242743bb6f93bdb9250f8a50068c994eb740636"
    $a6="1e362c2d9282db64245523a78a1396686c03ac820508cbef1989eef0155cbecc"
    $a7="1e362c2d9282db64245523a78a1396686c03ac820508cbef1989eef0155cbecc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}