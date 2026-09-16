rule nthash_hashed_default_creds_mcafee
{
    meta:
        id = "45zsitMB8HPKu3Z0IDA2ys"
        fingerprint = "2e8b09ff75097469c5486cdae073aa3e9358055c4641cc4f80f673df676fe663"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcafee."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="25e0fe545755d728303735bc98a418fe"
    $a1="80c5edd2a913266ae3907e4de1348e42"
    $a2="3008c87294511142799dca1191e69a0f"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="d1db8fd072323acae3b0d91f9f583e88"
    $a5="cc82fb78c3a48e6522cb0385d8e66f4e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}