rule nthash_hashed_default_creds_compaq
{
    meta:
        id = "6Uoy4AXdsjzKyfRtPVOdbC"
        fingerprint = "09f9d53f1546b6c9c959bd4a8f755a6da0a440e38bb15017bf8f7cb23f48995d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for compaq."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="d144986c6122b1b1654ba39932465528"
    $a2="989135220b8d9f7a57076280ac93c76f"
    $a3="28eaf4e2b4606dc8e368e2c2a405dfa8"
    $a4="a4141712f19e9dd5adf16919bb38a95c"
    $a5="a4141712f19e9dd5adf16919bb38a95c"
    $a6="e337e31aa4c614b2895ad684a51156df"
    $a7="e337e31aa4c614b2895ad684a51156df"
    $a8="db51013b2730e1f16df6db7c3a73ad60"
    $a9="57d583aa46d571502aad4bb7aea09c70"
    $a10="57d583aa46d571502aad4bb7aea09c70"
    $a11="57d583aa46d571502aad4bb7aea09c70"
    $a12="f938b53b982f22cd6b1c14ae10665480"
    $a13="329153f560eb329c0e1deea55e88a1e9"
    $a14="43a4477335c84ba91f310bde197cdbbe"
    $a15="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}