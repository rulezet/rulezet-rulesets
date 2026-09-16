rule sha3_384_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4f133e2a2a99c2f4f761f061678bd7ef64245d4d6f1452db9eb62e15bbc7f5e348fd972e8359ffb9e4229d2aad1a8787"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="9ebc8b83e466b0345cd577dba27a2e667c2c170a471f4867699b8f35d9a5fb2acf365e2dfe002972553339c8f440ace0"
    $a3="4385f1dc4c75de3575b22ab0d91156473f89fa8191f41092bf6d55053ab2236d1c6609191e138608d8ab584c33b21baf"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}