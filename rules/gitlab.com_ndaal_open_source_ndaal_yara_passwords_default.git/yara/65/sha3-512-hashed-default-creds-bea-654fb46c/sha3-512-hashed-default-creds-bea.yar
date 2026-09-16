rule sha3_512_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a1="085294bc9669dc8d9591758b9caeccdd8127c9d6aac8d81bb55cddbf6fc01005f38332128ea682e92983cb7c3f033705a32295afa868a3cf989b4494aabc8fc2"
    $a2="9590db8c6413f2ef63a7c9c616a73be75b4c1a95fa38a802858077a9e2d4ad8b644be584e0457ed6248426dedecc970259ca575adaf1f0a171c9e0085617387f"
    $a3="097eb45ac7d97f03eebe74a62670a50bfc96e125833c3c43ef977745a9a656bfe0f16c9aaa187d04b2108e684022467086dc37e0e17e7e5983d3e8d10036af17"
    $a4="68aca6a399ef9122b29eaf0843ee168d5116c02844c49c2067efd3f6db9b298f6a558bac77e9a99a40fb386c31cc74cebb2220b3be9df685ccab1118403db033"
    $a5="097eb45ac7d97f03eebe74a62670a50bfc96e125833c3c43ef977745a9a656bfe0f16c9aaa187d04b2108e684022467086dc37e0e17e7e5983d3e8d10036af17"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}