rule sha512_hashed_default_creds_jaspersoft_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jaspersoft_corporation."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="26c669cd0814ac40e5328752b21c4aa6450d16295e4eec30356a06a911c23983aaebe12d5da38eeebfc1b213be650498df8419194d5a26c7e0a50af156853c79"
    $a1="26c669cd0814ac40e5328752b21c4aa6450d16295e4eec30356a06a911c23983aaebe12d5da38eeebfc1b213be650498df8419194d5a26c7e0a50af156853c79"
    $a2="ea1053d265ca4ec96319f3ee4dfffaf4e436e09c857337024d7cad5b07a6a79d0bcf71031b35a5afd99559f0b70db1e562aabaf0f0b26c7081a2fe91a352d591"
    $a3="ea1053d265ca4ec96319f3ee4dfffaf4e436e09c857337024d7cad5b07a6a79d0bcf71031b35a5afd99559f0b70db1e562aabaf0f0b26c7081a2fe91a352d591"
    $a4="0ae25a277f843f7494ad3600543fa0f8d81e935a9ccd6aaedef991fb2ab61e9f9f6ac02fe646faa3463d656cd57a6c161443238a1ed83501755af29e3d20e1c7"
    $a5="0ae25a277f843f7494ad3600543fa0f8d81e935a9ccd6aaedef991fb2ab61e9f9f6ac02fe646faa3463d656cd57a6c161443238a1ed83501755af29e3d20e1c7"
    $a6="2cff38a527697f0c8df41a644671718d7d139c9b6d836e126b62677d8b57b1598874b6b0595c10358f59ca4e943d8fd2aa57327db011a421a80ec65945ea210b"
    $a7="2cff38a527697f0c8df41a644671718d7d139c9b6d836e126b62677d8b57b1598874b6b0595c10358f59ca4e943d8fd2aa57327db011a421a80ec65945ea210b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}