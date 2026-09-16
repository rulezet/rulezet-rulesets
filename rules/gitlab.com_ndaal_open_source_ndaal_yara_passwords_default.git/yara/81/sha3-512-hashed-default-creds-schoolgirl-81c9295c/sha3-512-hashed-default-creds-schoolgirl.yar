rule sha3_512_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="763c330b6175d4a172a4e31d6a4eefc9efdeb6df149e90994ba6d7fd820dafabe2f543bda52f4f2248310b615f1132db8dea2d1d6e21bd5407ede1d6932ed5d0"
    $a1="fef5efd101af901ea0256757648220495152b887fb6517b44605a3b28afcffd622e7340ba8f4aa3a79aa6770955509485d21ce0e890256c40450cba6e18fdfe1"
condition:
    ($a0 and $a1)
}