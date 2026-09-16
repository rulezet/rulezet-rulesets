rule sha512_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d57c797c20fa47182c80d1e4ff32f2dd292ccb686d294072ab050ea4cfd6f4b26d089c642fd6cf1b1710891f343f0a686a52100ed67ebf2fbdfc0e27c08a4cbe"
    $a1="d57c797c20fa47182c80d1e4ff32f2dd292ccb686d294072ab050ea4cfd6f4b26d089c642fd6cf1b1710891f343f0a686a52100ed67ebf2fbdfc0e27c08a4cbe"
    $a2="4280f3eebeb1ca3f6b401d448d1963372b5ccc66b69b645347cbed493b982e0ba238a780be72bd3d9fd79be3bdc899e5fd5e8ee11e2a2a1e64158cafbb18213a"
    $a3="4280f3eebeb1ca3f6b401d448d1963372b5ccc66b69b645347cbed493b982e0ba238a780be72bd3d9fd79be3bdc899e5fd5e8ee11e2a2a1e64158cafbb18213a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}