rule blake2b_hashed_default_creds_questra_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for questra_corporation."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a1="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a2="77624d56a248248e8e69e709013ba737bf2f5fcd1d43547be75523acdcdc61a08c993cb136789cfa62dd049d29aa59abc391537bcc9b519a31b7eb0d00b3c849"
    $a3="77624d56a248248e8e69e709013ba737bf2f5fcd1d43547be75523acdcdc61a08c993cb136789cfa62dd049d29aa59abc391537bcc9b519a31b7eb0d00b3c849"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}