rule sha512_hashed_default_creds_tellabs
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tellabs."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a6093490b11cbba15ec004d1c7da133c8c38c0a0c8ab34c3bc9d786bedabc3b24578393717f4edce5a84688192a283fb7950c0f00bd56964d1b0be5bd7c7cdd1"
    $a1="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a2="af2db999fc4948fdc482d48032d00a445911e2a26eb865291f424dffe3d563630913fab7b558cd83e38ce19f7e8676dbb9f4f3889b7299480920656912ccb3c1"
    $a3="166475b7cac12238c4cbb69f4c91d93b0fd2bf7ea3f09bc2002fadc74254a338880011630a3b6f714bb5116bab775c381bd457256c5d992f7526deb9d13ff60e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}