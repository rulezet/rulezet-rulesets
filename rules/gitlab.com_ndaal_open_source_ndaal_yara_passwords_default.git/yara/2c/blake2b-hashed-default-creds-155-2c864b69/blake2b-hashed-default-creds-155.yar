rule blake2b_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="49fffb0b9ec4bb472321946ddeeff90bb82b4c637b54dc647a1c42a627760dec09e44b1c997af5b9b333b00485f7344945e724a79687c6a6bc90bf11081e2365"
    $a1="1261c79e61aae75b7c20e76f0e04c29647a6effdc2d41a7a17582402fd6858060bf834cfa56771a1afa7b5da1ac3bf9eaae3d96fea8873b3eb17b48e9b733081"
    $a2="e61e21ceb5bc71f78b38263da5b67fc43356d4496918503d44af171fc8b80fe19d144524370712c245f5a71a217ef04e65169dd934cf3685d9af46017962bba5"
    $a3="e61e21ceb5bc71f78b38263da5b67fc43356d4496918503d44af171fc8b80fe19d144524370712c245f5a71a217ef04e65169dd934cf3685d9af46017962bba5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}