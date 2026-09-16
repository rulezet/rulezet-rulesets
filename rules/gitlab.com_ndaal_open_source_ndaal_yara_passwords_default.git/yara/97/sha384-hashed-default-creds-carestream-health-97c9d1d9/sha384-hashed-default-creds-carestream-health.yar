rule sha384_hashed_default_creds_carestream_health
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carestream_health."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f361309582f8317b4bc33adcd743e00e8c11b5eb73ea4aa38f0f092f8d13337dae82de6d71e9e969045a234977e9d189"
    $a1="23f52cb8538a8014acef759c20e2d17368e306e7cb31e9107bb1fbe18c4ab7bec3016255382e3689c2ddd7aeb7041388"
    $a2="f361309582f8317b4bc33adcd743e00e8c11b5eb73ea4aa38f0f092f8d13337dae82de6d71e9e969045a234977e9d189"
    $a3="c045cd6c70f420905b9fe0edd0e7272fa776a2bfe6d23d4a93551208e819b29ef77f17b03f57d53b31f3309879148614"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}