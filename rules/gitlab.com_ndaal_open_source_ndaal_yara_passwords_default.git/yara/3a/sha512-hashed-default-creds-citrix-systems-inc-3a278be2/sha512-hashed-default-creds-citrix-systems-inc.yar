rule sha512_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bedbc4b2ce194d741691fe6693e3dcfb7d3d64d3cfbcbbbba0efb1059891d16f7eaa8b07c17b1a74b08ee7d67e8ea88ac4b8c9d3beff5efc32845c6574202dae"
    $a1="bedbc4b2ce194d741691fe6693e3dcfb7d3d64d3cfbcbbbba0efb1059891d16f7eaa8b07c17b1a74b08ee7d67e8ea88ac4b8c9d3beff5efc32845c6574202dae"
    $a2="8fa46b8c73e1d37a5c0caeb40bbd4fec341988ffe54af0996ff59929b49fd88246f2c650c0e5e5ae8a55f1771a4c22aca3dfd06ead066318ae33cd893aaccae1"
    $a3="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}