rule nthash_hashed_default_creds_honeywell
{
    meta:
        id = "479cDZpVXuU95zfGPsTwhU"
        fingerprint = "6721c97d53a0344529ad97be7bb6f234ad005480a1d398918dd91c3e595b8db4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a1="a4141712f19e9dd5adf16919bb38a95c"
    $a2="f6121e705ff655db0198e763cdc2182d"
    $a3="d80e575c290a4ba7bd13b3d96d42ee25"
    $a4="5debcd2e1ac34eb2e7074db0ccc10bea"
    $a5="6edfce593ee38e9741b3ae0ea40a9a2c"
    $a6="823893adfad2cda6e1a414f3ebdf58f7"
    $a7="3d2b4dfac512b7ef6188248b8e113cb9"
    $a8="3a319c268a4be273a28450db17e6c18e"
    $a9="494707493dc9b83a1dab7c6788cf2e52"
    $a10="209c6174da490caeb422f3fa5a7ae634"
    $a11="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}