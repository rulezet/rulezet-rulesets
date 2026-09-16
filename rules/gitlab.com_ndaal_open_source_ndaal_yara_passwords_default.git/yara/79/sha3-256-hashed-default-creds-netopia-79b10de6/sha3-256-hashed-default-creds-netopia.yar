rule sha3_256_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="382eb1cdd10deb82263887f746b3b5d52070073fe9e598aca2432874270c56ae"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="981c96a9a479cc7f3353cddf89d90e04fdf10993fb43293c17b06359242ef8cb"
    $a3="981c96a9a479cc7f3353cddf89d90e04fdf10993fb43293c17b06359242ef8cb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}