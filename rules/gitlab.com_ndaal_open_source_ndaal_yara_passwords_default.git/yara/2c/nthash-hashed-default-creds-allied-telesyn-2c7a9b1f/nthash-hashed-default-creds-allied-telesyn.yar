rule nthash_hashed_default_creds_allied_telesyn
{
    meta:
        id = "2JjXy4XnnoOnTYMqGhiMMI"
        fingerprint = "9966729d6b5c6c2cda914bd6bae21bcf538a15435c5e078437311ac786fa3029"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f938b53b982f22cd6b1c14ae10665480"
    $a1="f938b53b982f22cd6b1c14ae10665480"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="f938b53b982f22cd6b1c14ae10665480"
    $a4="99d479d0a424c9ecbcb67568c4889239"
    $a5="2e810dd7bf85d71280f588266c1e2ee7"
    $a6="99d479d0a424c9ecbcb67568c4889239"
    $a7="f938b53b982f22cd6b1c14ae10665480"
    $a8="25370f2e5cf8d152408a610c4939e67e"
    $a9="25370f2e5cf8d152408a610c4939e67e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}