rule sha512_hashed_default_creds_carestream_health
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carestream_health."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2ded69cac172a65f38e5045599ec77aab09f30505c6095860d3d0e2cfb7e5c2d60fde6f96f6ad2b0b675329dd8fd573b6cac2242a8cd783383c3668684368649"
    $a1="3cea291f4518daa07d514419645d833d3ee1aad28befd65cbb74bbee56585502722f0662676d6c5f69127c92ffa3de8991764902bdaceeae76b5958ca592320b"
    $a2="2ded69cac172a65f38e5045599ec77aab09f30505c6095860d3d0e2cfb7e5c2d60fde6f96f6ad2b0b675329dd8fd573b6cac2242a8cd783383c3668684368649"
    $a3="e48142a2ea8da9a97454aba4e985ba72e9effd2e26324b065619d700bf7303b423462e6c853197fdb99d8f91d1c253780dbccba99dc588346746c9265afc7cf7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}