rule nthash_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        id = "dOA9I3fR6OmvBVQ8BzmwM"
        fingerprint = "65eeee4dcf53097a78ac5b725d7d43c7ee256a0459bfa637a505f0b8a69e4506"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="d144986c6122b1b1654ba39932465528"
    $a2="8846f7eaee8fb117ad06bdd830b7586c"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="a7ff3f3dfe4c1faf2d06c3f83105a5a9"
    $a5="7276ff2f82204f4161a2df026da20099"
    $a6="a7ff3f3dfe4c1faf2d06c3f83105a5a9"
    $a7="442f3bcbd926b51d5a84acdc82b4a4b4"
    $a8="823893adfad2cda6e1a414f3ebdf58f7"
    $a9="823893adfad2cda6e1a414f3ebdf58f7"
    $a10="9a3b1b48311950e7d2ed9c7308d5f563"
    $a11="a4141712f19e9dd5adf16919bb38a95c"
    $a12="c9d793a5059786e1a424a20827d73ca4"
    $a13="a4141712f19e9dd5adf16919bb38a95c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}