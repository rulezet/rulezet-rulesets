rule sha512_hashed_default_creds_osicom_datacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom_datacom."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="349a41e67bd69bcb66aba203c61d4c58e9912b1e46aff23bcb6ea6fab11cc9cb8bf25c5187a1b73f53d31be856fdf58b0ffe662e6df96ababaf2ae6a9c838cd5"
    $a1="349a41e67bd69bcb66aba203c61d4c58e9912b1e46aff23bcb6ea6fab11cc9cb8bf25c5187a1b73f53d31be856fdf58b0ffe662e6df96ababaf2ae6a9c838cd5"
condition:
    ($a0 and $a1)
}