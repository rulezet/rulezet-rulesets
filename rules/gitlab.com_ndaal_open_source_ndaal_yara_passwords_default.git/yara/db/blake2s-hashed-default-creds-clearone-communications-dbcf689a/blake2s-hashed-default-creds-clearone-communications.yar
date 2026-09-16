rule blake2s_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6f00f0e3472200fe1005639680b0b8d1a42eff76cd201b0f35acca2ad3d5a193"
    $a1="f40cbef85f9f77e707d6dbdc17357d6131cb28a2394c0199143e0ea7c61b4b2c"
    $a2="622f4e8dc501cd4902852c92315a523b95562fe0dd38d5d2eddf6193c9244e97"
    $a3="e0ba7472698e0f397e79d90df4161c49e98901be880d7bc867e19fced3446487"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}