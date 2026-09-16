rule sha512_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="31d76799e3d86137c1b9554ba3252bcfeaf44496e84bd251a97e909e07aff3b1fa91c7deb7dfd3c6534c1b4c790d18949c742da853165bf7e2c7c15abe1f85fe"
    $a1="38b6664d0f52faf6020a6959f21ccc36c03d322f61cc6e23d644b6fe5444551c59bf2610ff6acf12a517d2ae18d53db088ec3774bc75cfbc677ca8b5f9ae2fd2"
condition:
    ($a0 and $a1)
}