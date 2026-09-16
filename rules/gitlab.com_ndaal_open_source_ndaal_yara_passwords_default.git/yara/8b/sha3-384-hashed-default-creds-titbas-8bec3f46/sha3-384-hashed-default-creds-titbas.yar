rule sha3_384_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="73f67733846f098795e6ad87aee12c7540a5010c3589891c7f1006d8f0a98092a87a544071dc2d91a18567e218d07376"
    $a1="8d1c35d23636f3a4437e936a6ceb0d3b6dac6873b84042df6860f5263853dfec30462c0491ff6dec497b0ca1958c2f5e"
condition:
    ($a0 and $a1)
}