rule nthash_hashed_default_creds_allied
{
    meta:
        id = "4JHvTnZFj6Tki25Un1OAed"
        fingerprint = "2e53c80e723b6a24a9821eb1035791110b949a7913052df4ebbf2ba53cf09414"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99d479d0a424c9ecbcb67568c4889239"
    $a1="f938b53b982f22cd6b1c14ae10665480"
    $a2="25370f2e5cf8d152408a610c4939e67e"
    $a3="25370f2e5cf8d152408a610c4939e67e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}