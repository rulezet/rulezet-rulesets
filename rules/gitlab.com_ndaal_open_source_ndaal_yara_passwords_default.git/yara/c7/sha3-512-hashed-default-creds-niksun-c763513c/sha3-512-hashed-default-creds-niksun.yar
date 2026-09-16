rule sha3_512_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c304b99f8171cfd5c4c914cdc0a88a95ba45fcf7a49bd6effb87c53a7a825cc2d50284cdc1fbd2ebc66d0a05fcd24b475d00751a23604b60a8f2f92112fa83b6"
    $a1="17b284bf77f2a2b42a49485e33002c8c5dbbcfc351c7bebf5579f3db326757513fdd6e07da24bc30bb2007004383b7b0ab64fcbff238eb8c10763a5fac54f08d"
condition:
    ($a0 and $a1)
}