rule blake2b_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d45231115688f6712ef6ba4b634421bb0026fd06105c28785888dfb2f6145b1481f9c43c0c3dc9464f5dbdad787cbfd983f8e9076fc9292ba2afb56a67f631d"
    $a1="f05cc1dce30522404088964d1d989a90a5e73960f95e2bb823058768cab802b81413bfcc8baa755c2319bccccf5255686c9afaf59c769ecd4d2cf66b13d133f1"
    $a2="816a55c89d2372acb1f4c7071b3202eee9807f4befee4f1528400ccb8510adf4d7fb6c15e5b627bb51af1e6721eb5f3bec99d1d23a38f68eb1d14358733893a4"
    $a3="816a55c89d2372acb1f4c7071b3202eee9807f4befee4f1528400ccb8510adf4d7fb6c15e5b627bb51af1e6721eb5f3bec99d1d23a38f68eb1d14358733893a4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}