rule sha3_384_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a353fed17cc1f251167abd4921a2f11817a257ba9a6736a9bee067d95ccead16fba1311aeb59528b350331b95d30ac4"
    $a1="2a353fed17cc1f251167abd4921a2f11817a257ba9a6736a9bee067d95ccead16fba1311aeb59528b350331b95d30ac4"
    $a2="fe42f6d891df10ae003a6b3e1ddd8ecadfe95588224ea50002d617efdc2410d00c2fe169f5dc0e6e583b35d91e95947d"
    $a3="fe42f6d891df10ae003a6b3e1ddd8ecadfe95588224ea50002d617efdc2410d00c2fe169f5dc0e6e583b35d91e95947d"
    $a4="6c71a396a1be305d3f903d32b0639fe5162d594048a93cd940ac4c536a42d495febf2196478b8dab28b3fa5ed4752915"
    $a5="6c71a396a1be305d3f903d32b0639fe5162d594048a93cd940ac4c536a42d495febf2196478b8dab28b3fa5ed4752915"
    $a6="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a7="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a8="e073fc2dcd9ab5ec92b8aba9a77fea6e75646cfa25c9033a30ad0928367dbf240588a9f5ed0107ddb6eeedfa0115b3a5"
    $a9="1b9bfc4a37fe08188b1a0183be30ee8669002bd2012eda9636f8718bcd389bc7c3612b6c4d8ee2a627d354977c364a55"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}