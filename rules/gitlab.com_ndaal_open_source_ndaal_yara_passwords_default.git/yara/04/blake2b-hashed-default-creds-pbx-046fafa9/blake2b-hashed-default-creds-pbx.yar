rule blake2b_hashed_default_creds_pbx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pbx."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ed01ae8b43d770e67b5fc02e5944f8f95b234aa560d800e5514d54757e93b9de6a0032bb02b292e53c356481db06af63c9c14189c81169977ccace271c65a698"
    $a1="e61e21ceb5bc71f78b38263da5b67fc43356d4496918503d44af171fc8b80fe19d144524370712c245f5a71a217ef04e65169dd934cf3685d9af46017962bba5"
condition:
    ($a0 and $a1)
}