rule md5_hashed_default_creds_apple
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apple."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c9fb847d117531433435b68b61f91f6"
    $a1="63a9f0ea7bb98050796b649e85481845"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="63a9f0ea7bb98050796b649e85481845"
    $a4="4e372b1def6af8301435f3f81ab9d965"
    $a5="532c28d5412dd75bf975fb951c740a30"
    $a6="4c9184f37cff01bcdc32dc486ec36961"
    $a7="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}