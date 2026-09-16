rule sha512_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a131635fe38c1e8f066bcfe9afb910af375f67ed60f866208c0857a0de829780c276a474f64d6ec49beb1a77fb190b2b807073d3a3e2edfbf71d082c003f7d9d"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="a131635fe38c1e8f066bcfe9afb910af375f67ed60f866208c0857a0de829780c276a474f64d6ec49beb1a77fb190b2b807073d3a3e2edfbf71d082c003f7d9d"
    $a3="2cff38a527697f0c8df41a644671718d7d139c9b6d836e126b62677d8b57b1598874b6b0595c10358f59ca4e943d8fd2aa57327db011a421a80ec65945ea210b"
    $a4="f724623e7c0fcf5b2b27bee13bca3a4c9f1bf9f969ea9671c8a9964b740b5adc716e5f025d62af042682c8032d9b150da9a6fc57a8e99c9f4d69aa3e788fbf21"
    $a5="b4ceae0fd10ba7beb0e03368279a1f93487b4b915e8761655bad09e8399f7c56e60bf7d0ebe648b0f5eb0c60f1c817acfa505196a3543b4f5d31c9e02530781c"
    $a6="f724623e7c0fcf5b2b27bee13bca3a4c9f1bf9f969ea9671c8a9964b740b5adc716e5f025d62af042682c8032d9b150da9a6fc57a8e99c9f4d69aa3e788fbf21"
    $a7="9ac7bd4b9286e4e03dcf7c98b7200a550663158eea9a7693d09f78de94d5c360ce47a5cc7336cfe4e51883b27be25d7e1ccf9a99d02ba6632324dcb1ae3e2d90"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}