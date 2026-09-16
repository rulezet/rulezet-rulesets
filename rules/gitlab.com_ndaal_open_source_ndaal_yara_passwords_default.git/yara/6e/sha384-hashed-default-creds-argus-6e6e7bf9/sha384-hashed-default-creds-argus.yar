rule sha384_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8dedd9fbb2b8711a25753f2faddfd4c7478f584e8f9ee89328f3fdfab770ee19abcc7fbae828335f73500137ee4091b9"
    $a1="103e5f1cc41a1c63748322481e57b28d0abb36a5c0501a2e1f0e9f1357f99867a30d76a844904a52d319525ac0d4696a"
    $a2="0bc7b52b007a84f31288d7e99b499e8f7528fe05baf75303da65e1c361ae4132e117fd7b2b40e4eda69cc420eef0dde7"
    $a3="0bc7b52b007a84f31288d7e99b499e8f7528fe05baf75303da65e1c361ae4132e117fd7b2b40e4eda69cc420eef0dde7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}