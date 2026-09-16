rule sha3_384_hashed_default_creds_hitron_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hitron_technologies."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="ec6730a0d5a973480ab6f21748f6e95a1779590932bf6f460b6f155a04e4a1eb6334bc198d2e571c77f1418ef279d865"
    $a3="9cb486850c52d68ff2858c919e2fd0a8d871e132a529fdaea9f2f11bed73ac2833cd03f13cac372c585c06a74b40f844"
    $a4="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a5="768e9f484407d2d3f91ef8ede60886837c48cac9409422b9ac17fb296fe5bcbee2fd72215b97f6b8edbe0c51b3c090eb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}