rule sha384_hashed_default_creds_stulz_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stulz_gmbh."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="85979ba3d910ba87ca77648ccda9696bb27f8b3777179838f20df90b40e25a067ae7ead01ee6aa1fa4a9caeb1f083f24"
    $a1="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a2="f55ef5873dbd448a3d39e0f3ec4c7325d07d6c8386a3586fdcbbef22654155fb00a1ccc60e40c5fd878c6c72e1b6003e"
    $a3="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a4="3803b4f09086642a4c645198753c9663b2811c94883eba81c688bdd1be924f3908274c43a66192e92f4cc1e3716aabae"
    $a5="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}