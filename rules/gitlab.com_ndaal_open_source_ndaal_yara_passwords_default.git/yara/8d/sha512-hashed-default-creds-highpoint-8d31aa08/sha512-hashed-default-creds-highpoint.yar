rule sha512_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8034aa85cb386cc24e948bd92148943cc56a7988d035b7a3e5b094f2a7ddbda85da8cb80ae9952e16018c8167da6641e792c3a2cb888ec45629dbc22d9ec75fd"
    $a1="101b271ffca2c6d7d1394e5ccc45e7130b9f72541d048d66a5502bafd26c3a43c4ee38b1aca0f523b9c0760ef88c01a14f710da91d6946d8dbde520b0d291c57"
condition:
    ($a0 and $a1)
}