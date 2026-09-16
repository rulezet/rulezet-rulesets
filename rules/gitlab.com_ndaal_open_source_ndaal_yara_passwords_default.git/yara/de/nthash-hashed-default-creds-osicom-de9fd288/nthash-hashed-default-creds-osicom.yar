rule nthash_hashed_default_creds_osicom
{
    meta:
        id = "3WAjyaYh3hhSuwJBfCijYA"
        fingerprint = "459e807489737b589a822ed934162bff46a4b36c4ebe59f5c46ba5811481624d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="94aa68f72ab39cfec7ffcb58dca3358c"
    $a1="94aa68f72ab39cfec7ffcb58dca3358c"
    $a2="ec16b699514c70c7f3e12ece7c30232c"
    $a3="d47ce0c3e3f78529db2f266d5e7afe8d"
    $a4="823893adfad2cda6e1a414f3ebdf58f7"
    $a5="823893adfad2cda6e1a414f3ebdf58f7"
    $a6="a25b2710ba9de114396adc7dfb0a7235"
    $a7="2e810dd7bf85d71280f588266c1e2ee7"
    $a8="0280777f37d4f4e7c478d21cec701463"
    $a9="ec16b699514c70c7f3e12ece7c30232c"
    $a10="0280777f37d4f4e7c478d21cec701463"
    $a11="0f646870e4bfaadbf772e378b0e69777"
    $a12="0280777f37d4f4e7c478d21cec701463"
    $a13="823893adfad2cda6e1a414f3ebdf58f7"
    $a14="a25b2710ba9de114396adc7dfb0a7235"
    $a15="94aa68f72ab39cfec7ffcb58dca3358c"
    $a16="2e810dd7bf85d71280f588266c1e2ee7"
    $a17="2e810dd7bf85d71280f588266c1e2ee7"
    $a18="0f646870e4bfaadbf772e378b0e69777"
    $a19="0f646870e4bfaadbf772e378b0e69777"
    $a20="6c692ee01b2fc655b6cd60195a4a3be9"
    $a21="43b4c4b0d87e82b0bdc9c8f6a110fe1c"
    $a22="532a71d1afa4930012f3048d25f98148"
    $a23="a444a17d659890b5a712d16b50fb9a08"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}