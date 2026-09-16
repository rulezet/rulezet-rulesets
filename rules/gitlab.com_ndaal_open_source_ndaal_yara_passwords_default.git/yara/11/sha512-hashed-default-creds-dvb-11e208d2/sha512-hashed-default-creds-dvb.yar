rule sha512_hashed_default_creds_dvb
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dvb."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="57965510cedf7d994e59554539cc43a423edc10a04bbd1d0deab5873d9e155eb9f5722559c40ea27a4c6ed012585832dd40a10a2b8f1faec35230066554a0f94"
    $a1="86c8974bdfd288fe33c01169ad58565ef0fd1b7df38afa96ac26c28647e7d78acfb69edc13b18cd35b5b4763f9aab91cb70c427fa5a621f82e9f6207c3ae7d4e"
    $a2="7312a19110e6bcbf4a19c7b284019d058f9c9e9ed891b9138c17818ecfe47c671bba4aa70720f5a58442c60f921a9a925f5273d8a16c66ce6ecd635ec22637ee"
    $a3="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}