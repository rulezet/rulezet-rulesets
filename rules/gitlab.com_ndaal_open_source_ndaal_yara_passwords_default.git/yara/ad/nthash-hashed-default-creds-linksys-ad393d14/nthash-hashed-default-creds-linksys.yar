rule nthash_hashed_default_creds_linksys
{
    meta:
        id = "7VuS6B71dpyBoXcSG6zLOd"
        fingerprint = "77bd3326214f7ad8fdc45eaeb02a1b564c0043e644f1d912a1652c0e6579dcc9"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for linksys."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="71267972ece8cd2f1644fc2f701bfe24"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a5="0e40e522913565543295e2ee51721a57"
    $a6="209c6174da490caeb422f3fa5a7ae634"
    $a7="d144986c6122b1b1654ba39932465528"
    $a8="68ef914901557e4dee565f8c126134f6"
    $a9="57d583aa46d571502aad4bb7aea09c70"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}