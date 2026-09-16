rule sha3_512_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a587c7f961b13921a8b6e438999a5ea931d36a2c404695683db03a5a601c01b623b2369e5e659cf51c13e93101b6ec5fe2770eb7ee91c4520e0fa5a6e99c0ef0"
    $a1="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a2="a587c7f961b13921a8b6e438999a5ea931d36a2c404695683db03a5a601c01b623b2369e5e659cf51c13e93101b6ec5fe2770eb7ee91c4520e0fa5a6e99c0ef0"
    $a3="21528e7eeb8e93cf2dac57b56fbaea7dd91e60bf3242155a33eb957d368a9d636a8b7ea4148f6fd73ffbb4126a20c8b84c3e3446d76179c3701626677dd2420c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}