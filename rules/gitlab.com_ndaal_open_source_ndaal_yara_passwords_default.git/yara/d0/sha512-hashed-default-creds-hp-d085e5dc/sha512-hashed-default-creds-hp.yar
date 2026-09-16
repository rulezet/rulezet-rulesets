rule sha512_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a1="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a2="c83ea6f5d6969ec74b328b33c24eae28063248ce31a514b182cd1d8e76bacf37a659e6c692441a34e06f237f5679c218f9cda23071ad0985e7036dbd599c1999"
    $a3="33df2dcc31d35e7bc2568bebf5d73a1e43a0e624b651ba5ef3157bbfb728446674a231b8b6e97fa1e570c3b1de6d6c677541b262ac22afda5878fa2b591c7f08"
    $a4="6bef213757e5e55afb30df047e9f184540a265c70b4ec81aca44d11f220f3ca2bb89454d7336950adb1cdfff9fd6ad63356550fdbae69d50f07ba420cd6cb38e"
    $a5="c5fd7fe71a670e3936ebd103f501d9ad9ac4053d95b743f01ad9ece7c2593ee321d08bcd832b4562b8c8941ae1426ec9aa196c7a0f5b46883696a5306a8b29a5"
    $a6="e2cb708cfcafc329b761f054f0fe9a41a086edf5bc55ae3cb6029c6e34780265d48597d7cd38c0b8b8c77e36b154c442b5d88fd3a1d5c9aa9b94557abf628397"
    $a7="c5fd7fe71a670e3936ebd103f501d9ad9ac4053d95b743f01ad9ece7c2593ee321d08bcd832b4562b8c8941ae1426ec9aa196c7a0f5b46883696a5306a8b29a5"
    $a8="61f884b03cc8fde3d6a670187589df8475a31dd581798bc195f136ae0ebbae9a79648e177d698e0bb1e1fa74c6870aad35ecba53fc114c16c877c980b77a0904"
    $a9="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a10="8ea15870987d34972ee28de0e6b8ad0217970d473bb0414911753e8a1101cec81ba9f6b0db7fec16b2d0b9cd4c91337896ebdaa033b47955f620834761415c44"
    $a11="5938d9afe029dfd7976b6a64a0535d4abd93801616424098b81ff72daa04cb1c24daeb6397ce04a542405513e4c35746756d328a7f21dd99d5fada7261a25441"
    $a12="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a13="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a14="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a15="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a16="c081a17087cd1e8c2c48a10b344823948044be4ac680a0224b953e1734f8fd9e645deee5fee364e996e5e9af0d4948ea2f98f95857e4ef070942bdc86da8cc25"
    $a17="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}