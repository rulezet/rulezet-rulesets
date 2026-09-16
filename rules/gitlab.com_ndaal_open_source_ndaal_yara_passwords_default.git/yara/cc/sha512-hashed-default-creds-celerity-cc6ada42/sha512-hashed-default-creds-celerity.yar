rule sha512_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="22bbcb9e5de1c4a19aaa965c115d80760ad6fb61d68a13c2755bdb82915fd67eb6a85ec467345b1420ebeac20cb6b31b7146de7bd566032edf24cb3cfbaed174"
    $a1="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a2="9fb41e98ac839e0d5b5f18a038a269e34786dc87c7cbfbc9f860ffe9974471f6fa72c63d7e2b1931193541f1f780490eb6c191c32c9d628623d8bf87490260f4"
    $a3="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a4="116dc22a3af6a6f6e3d4e64c22b3d6d384d7819257043c3c7d82c74c17addf146aa38a5c11f7eced518faf90b94ccd87a5e183cd228889e2d09e11dc0edd6655"
    $a5="116dc22a3af6a6f6e3d4e64c22b3d6d384d7819257043c3c7d82c74c17addf146aa38a5c11f7eced518faf90b94ccd87a5e183cd228889e2d09e11dc0edd6655"
    $a6="ead37dfccbcb3c075bd1380bd5ca94a590207b2779819eafbb4de534be08cd518c9a92f2d9006a2f8e1b1c6378cf799aab6cbb19ccb47b3a1a5116e1aa97b485"
    $a7="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}