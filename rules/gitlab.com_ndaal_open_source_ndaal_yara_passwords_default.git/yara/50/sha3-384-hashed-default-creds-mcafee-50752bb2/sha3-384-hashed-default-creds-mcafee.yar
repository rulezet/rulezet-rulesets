rule sha3_384_hashed_default_creds_mcafee
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcafee."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="975506b0b14eae10bbbf291e51ba718d937d8597c94d83e17fc0391e7dcfac1545f8725219b873135bd7d71a18f2c25f"
    $a1="0f67112ef7609ac784080ec00103eb0961ec3451c3bc846237fd7c57d67b6119f2735ab057a39b449ca7a807dbff2fa8"
    $a2="9150a266c71a4cf0cbd01a60608f395ec1f8f7082f4041e49195cad98f6ee0cb08efe60cb8d148d2e40520b33922bf40"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="f4bde4dd62815a5215fb03cf4168e256dbdd61d85a5a1cfc46e072ff6d06fcf97ca72e333b3a89192b77b0ed891fbef3"
    $a5="84a98ad14758f5dceb73743c42aa68c109a923e69d4c7c7a40cfb15552feb8afb6147e9e68c8a42f9c7f7fdd39950d5f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}