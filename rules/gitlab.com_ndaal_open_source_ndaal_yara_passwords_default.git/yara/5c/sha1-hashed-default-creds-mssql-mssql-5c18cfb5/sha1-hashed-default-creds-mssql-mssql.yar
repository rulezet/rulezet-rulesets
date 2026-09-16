rule sha1_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c78e476751ee6bd0056d9d5c6c6b959624784ef4"
    $a1="ae381151533f9617a3b09b6ca3fa2fd6b1334e41"
    $a2="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a3="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
    $a4="b2e98ad6f6eb8508dd6a14cfa704bad7f05f6fb1"
    $a5="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
    $a6="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
    $a7="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
    $a8="8d0ca8255d7305e13a9185ca8666a82d7a61908e"
    $a9="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}