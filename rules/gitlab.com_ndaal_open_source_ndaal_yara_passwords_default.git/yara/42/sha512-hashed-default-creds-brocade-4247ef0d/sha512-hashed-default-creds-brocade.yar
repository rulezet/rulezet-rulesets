rule sha512_hashed_default_creds_brocade
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for brocade."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="00972afc59ce76796d2622a1d88458ccb7ab2a9d919530da858120f957f7bb04583eb4f153801d2f3f11f0e7f4a9d00d153677bc5c5865b003a6c2b5b420fc58"
    $a1="b9d3bbccda0a4d0637df4e086a9f2e73f7a8e0eda030f75cc7d499b2907b1da15220b2a5784daec741c37ab5e3f97eab3ae5e091427f68d272060a8479278423"
    $a2="5f08037f9bb7550d408373dea93c0bf2be42b6b63f40e6c11f07f209757f48eceed04124b74b43d6aa52a760073e71cfecc6b4942f35d4b2e7b6650c2f4ba235"
    $a3="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a4="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a7="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a8="690c8c6f049d5113d83ff4ff996780bf2db62c1cc4cd93c3e10824d703c2a3636757c1d284bd5da2e00e605543406817b51c19bb2ad6782120b3c96ecdec87ac"
    $a9="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a10="44d3cf6a7598dddd40df331a2e1581faa7dd3b6e70eb5124b99e4012eed6b4977e34e7bb522f4ffbc6d4bf3f627f31e740f1ca3692a80b384e0b6bf94eeaacc4"
    $a11="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a12="e5141d9df152d8c4c74c0aeb22daad0e5ffa0670aa73c6ffc9e387c71f9b9cddb94bf5f9544275474f30a60f0ec7caa1fc20f898c68518993eea117c38766c40"
    $a13="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}