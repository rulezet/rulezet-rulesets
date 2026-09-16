rule nthash_hashed_default_creds_nokia
{
    meta:
        id = "6let6Rxplm5DbpjXwAgqec"
        fingerprint = "0221e855cc08215991099d0e18670ab72eb61a72052e6ab3c8fed5e67847be5b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="102019b0a021e7bf80a02f07167b8a74"
    $a1="102019b0a021e7bf80a02f07167b8a74"
    $a2="1c72ec33dcd8413a552d6563d7bb6452"
    $a3="1c72ec33dcd8413a552d6563d7bb6452"
    $a4="09e55a127f3d4e4957c77de30000502a"
    $a5="09e55a127f3d4e4957c77de30000502a"
    $a6="7a21990fcd3d759941e45c490f143d5f"
    $a7="42b1e57dca4ca18b8b08ec58344b38e3"
    $a8="2d033d5762adff596255b36b4be98227"
    $a9="42b1e57dca4ca18b8b08ec58344b38e3"
    $a10="dfa00d30923c6a547d53c92da85850c5"
    $a11="329153f560eb329c0e1deea55e88a1e9"
    $a12="43a4477335c84ba91f310bde197cdbbe"
    $a13="329153f560eb329c0e1deea55e88a1e9"
    $a14="7a21990fcd3d759941e45c490f143d5f"
    $a15="34686ea587a2c288b00bc7a2c3c67c3e"
    $a16="1cf0700926b37a30c826c8edf64339d9"
    $a17="1cf0700926b37a30c826c8edf64339d9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}