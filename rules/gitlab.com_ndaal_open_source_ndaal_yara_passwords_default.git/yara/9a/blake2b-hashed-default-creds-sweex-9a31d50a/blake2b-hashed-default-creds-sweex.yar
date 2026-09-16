rule blake2b_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="950b577e986853020dd0ed223ad7b34d1faf2eff2350ddb3c406ea1bbd73dd71c573e46f439d8a8ffb52928e69783477ab3badb9a33c7d0bd3a4dd59af4621d6"
    $a1="67394b512dbcda224a2ef0749cdfbc0aeb6e4cfb22a14e348e3838559b9dd0c960a7eef0335512bbf2752a5100ebb04ec13b434e6ee729a3cea726526eb69285"
    $a2="da77bd2a1d857d88b31de27536b81df7f005027d4f847667df13a0569b6048e0454ce9480827789547cc174060c4f388866ebb0209929b0de414cc9ac571c421"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="cddfcc68ad850c35154c6aca1a70c03adef9d253ebeda58b91c3028b3fe44acfac46ebf6d90a80810389b249845137a758dc0ab0e64d0b5a423080b068325b9f"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="ff86a58729d06321cc03154320194bd9c8de16777be446899c1575cb92e77a3c339152d163c9d29582bd542b7dfca28ab91dbfe7e1a57d489f18e7354e187ebc"
    $a7="ff86a58729d06321cc03154320194bd9c8de16777be446899c1575cb92e77a3c339152d163c9d29582bd542b7dfca28ab91dbfe7e1a57d489f18e7354e187ebc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}