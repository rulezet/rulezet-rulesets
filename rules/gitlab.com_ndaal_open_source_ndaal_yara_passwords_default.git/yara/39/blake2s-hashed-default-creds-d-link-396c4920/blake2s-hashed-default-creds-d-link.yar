rule blake2s_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="90931556d9513e8c26040a9ec2a2f1300bdc79a890907da9cc2b3a2c690574c1"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="4ed0f92da3ec1ff94b5ed67bfcb542e5045da6d0c80d4aa7008faba09f58dc7d"
    $a7="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a8="bb5724830d602461c479a652e85fc8bea49407f8d34442877195a37785fa86ab"
    $a9="911da23c815c526db1d0ca4b792f4962cba09ac0bd90662de650fd5cc29ddb1d"
    $a10="7c34faf3351e3df0d7958ecf36b094a5f3e1b677907cae2469c1ac1c22abefbe"
    $a11="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a12="a2102636135f50a3122fcb77ceb7876e77410a59d0bf1f38216e2be89e204c02"
    $a13="a2102636135f50a3122fcb77ceb7876e77410a59d0bf1f38216e2be89e204c02"
    $a14="57727f4c480364a98620378043300a7eb3aaefa12707912a6d486d4c0220d712"
    $a15="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a16="cdc2f0d214e9a7587651498267c8e1c65347b1061af15cb27b253dc4f2ceb482"
    $a17="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a18="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a19="f1aed680f8feaa588d1d5680fa45a227de69a6613f082fca5508dbcbd1d7a0c7"
    $a20="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a21="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}