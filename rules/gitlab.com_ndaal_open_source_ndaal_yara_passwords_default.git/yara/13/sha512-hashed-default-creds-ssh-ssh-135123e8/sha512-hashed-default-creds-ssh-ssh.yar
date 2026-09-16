rule sha512_hashed_default_creds_ssh_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssh_ssh."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c27cdede5067848ace0a2fe458aecab174f2d2966fe26f4cb5d5072e3270f2e22bb3f677fb2c16d0bbcaff2f2be76619f91672a4acddf84f8a5fc53af519529f"
    $a1="c27cdede5067848ace0a2fe458aecab174f2d2966fe26f4cb5d5072e3270f2e22bb3f677fb2c16d0bbcaff2f2be76619f91672a4acddf84f8a5fc53af519529f"
    $a2="1d8ae800c77cc8dfbc496582223362557b3215f7e18a22b3b8fb7787b2c02407055d21f6e897d263aa05608259646e064f92606973bce4968e93efb43397c64b"
    $a3="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a4="90009d12415ac46a2c7e4492c12bbbb22d7888011ca9aca98ac14837f210e110fc63b991f24f0d51dc4c18245e08cfd2d93380569ca3a00701dda743e9a08a69"
    $a5="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}