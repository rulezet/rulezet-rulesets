rule nthash_hashed_default_creds_huawei_ssh
{
    meta:
        id = "2V2vJ5vVy05DpyDnhWb9ac"
        fingerprint = "280d04a6f90751d00671dddd281763bca9353dd0e255d1d25d386a623e0a91bd"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="a25b2710ba9de114396adc7dfb0a7235"
    $a4="93b40288d6c38549afb951e5f6914fe0"
    $a5="93b40288d6c38549afb951e5f6914fe0"
    $a6="6bdf2e303596176ce000a52e2492676a"
    $a7="6b378d4ad5d07a4ed06b98a6fa917667"
    $a8="f2a32f242554b6b45d3556c8ecf537a1"
    $a9="57d583aa46d571502aad4bb7aea09c70"
    $a10="57d583aa46d571502aad4bb7aea09c70"
    $a11="57d583aa46d571502aad4bb7aea09c70"
    $a12="2f92e64faf5e4784805784954c97c281"
    $a13="2f92e64faf5e4784805784954c97c281"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}