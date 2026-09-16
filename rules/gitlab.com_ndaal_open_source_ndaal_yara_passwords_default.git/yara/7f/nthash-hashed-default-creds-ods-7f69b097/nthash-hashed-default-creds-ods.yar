rule nthash_hashed_default_creds_ods
{
    meta:
        id = "1AhV9023XUeRoXsrQoNm5N"
        fingerprint = "e126f4c93cd452f2cf719955190b439e6ef8234b8643bc7c6139e47b77775b6b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ods."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9a2ace12470d69667ef8ec6114bd4794"
    $a1="9a2ace12470d69667ef8ec6114bd4794"
condition:
    ($a0 and $a1)
}