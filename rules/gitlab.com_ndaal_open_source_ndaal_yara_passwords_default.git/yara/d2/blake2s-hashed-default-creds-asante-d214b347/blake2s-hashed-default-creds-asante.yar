rule blake2s_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="66e622a2084bf867e60d9ae77e0b98e69489074f5cedcc11cb68f066904f2ee2"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="66e622a2084bf867e60d9ae77e0b98e69489074f5cedcc11cb68f066904f2ee2"
    $a3="2538fd118f310b61a135cfbefc4524bfc4860d075ad19c7a9f1ba86dca1913ae"
    $a4="d78c0e6d974d867f9a497f92f842f8c634a6fc7cd92533c5f8ffa5fc1d24bec3"
    $a5="970afdc6ee2aecfa5da9427390b905b3401b71dcbb58170f5d1215ff3c5921d2"
    $a6="d78c0e6d974d867f9a497f92f842f8c634a6fc7cd92533c5f8ffa5fc1d24bec3"
    $a7="ce018efb2ee034f62d98168e7eb5c22e193421f872f561229f1e80202e1ca1ae"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}