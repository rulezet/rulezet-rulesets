rule sha512_hashed_default_creds_digi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digi."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ae78eaec2f17303958a31439babf58c6a2e30c49aac058782fa1ed34111ccd3920840619a362a8a2fd16678cb8ac888a7a27fb0ec9a2859426ee849c8898ec4f"
    $a1="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a2="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a3="05ee170f46fd6040a23ebd883d63ef3b2aff55e3d6e01eccbc401088d7de0c153251c27e517ea4ad9bed62980366d1a47ceb312a659e77debda650d870094562"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}