rule sha3_384_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c805854f8913a1dfd3ab24126f5babd95262447ff267fc9c97e21313165e6da535d9a37527757b6f80f522bc956d1d02"
    $a1="c805854f8913a1dfd3ab24126f5babd95262447ff267fc9c97e21313165e6da535d9a37527757b6f80f522bc956d1d02"
    $a2="1c33fb8b518f6d550863616cb2937ddc13c2b4a87f87db404b1507dea258cc5a1867f65c5ab27ec5b35cc29c016637e0"
    $a3="1c33fb8b518f6d550863616cb2937ddc13c2b4a87f87db404b1507dea258cc5a1867f65c5ab27ec5b35cc29c016637e0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}