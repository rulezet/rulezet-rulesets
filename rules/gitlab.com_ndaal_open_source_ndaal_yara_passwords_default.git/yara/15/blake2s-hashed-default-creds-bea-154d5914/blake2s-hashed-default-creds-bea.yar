rule blake2s_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a1="f4ccb9a16537e226102b6f5b85c2ace40d5140d0cda8c0ef07a08b8cca87bfc9"
    $a2="5ef65cc2ca9c5aea4bd3a676ebe0d4d0830ef86d040b6612912cfa92a177e919"
    $a3="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
    $a4="eb9a4c3626871a0b20c65170b823b5e26a50e2a6014956dace0350460d24a65b"
    $a5="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}