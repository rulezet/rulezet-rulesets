rule nthash_hashed_default_creds_hp
{
    meta:
        id = "2DXuVTUAbsfRf8wdoDykGi"
        fingerprint = "8be9467dfd3ea92aab1e59f6f45428fff011b352df59e38be5724aed8d739229"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="26c1dbbdd50f555d5a23dd9d79fcba82"
    $a3="f80ca594861bf6e652164cade78e89ee"
    $a4="de2c13ee8d8b209e671629bb28783541"
    $a5="51b447c257949292c6c55e4e98fa06e7"
    $a6="47cda1e3ab2c33e7369db5a86f251fef"
    $a7="51b447c257949292c6c55e4e98fa06e7"
    $a8="969de145905a696de8e5f37e292527e1"
    $a9="209c6174da490caeb422f3fa5a7ae634"
    $a10="880aa8beaef65966121e8d79ed8b42a6"
    $a11="d94dcf92d61d9df33f60a402b4d61755"
    $a12="209c6174da490caeb422f3fa5a7ae634"
    $a13="d144986c6122b1b1654ba39932465528"
    $a14="209c6174da490caeb422f3fa5a7ae634"
    $a15="209c6174da490caeb422f3fa5a7ae634"
    $a16="9e056d37ecd6346a9116e35456f148a2"
    $a17="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}