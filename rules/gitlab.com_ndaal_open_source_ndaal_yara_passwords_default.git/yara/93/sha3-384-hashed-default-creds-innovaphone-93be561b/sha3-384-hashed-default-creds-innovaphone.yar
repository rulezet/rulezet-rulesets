rule sha3_384_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="83f7ec87323d1a00326fe103355b91829166b5178f4f7ac418885ebdc9881b3dfe2f7b6728e5cb75a7b0369718c84f7d"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="ffaec14c60219c82b4b8ad584fcf7f8c640b64380dce51a1811f7c6c98a3c9f8d07e66b4dcf05f56eaa05de9e57a5eef"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="cdacb28f67e273a3324952715f195a99303d8d313c0859e6eaf578599d69059f6e5c0381e702a85841f438d6d696e777"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="39b4e90e161df46f104086a15c6f7ac48c0cd4685a4bd34d971ce04805007ee0d6536fae0b1799e1ac0a172f59d52518"
    $a7="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a8="7f3542e474fbf328862ddd1348b0eadbf197fca57b80993089a3f62ce07b76564e8cc37df66151f3e168b4970c351032"
    $a9="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}