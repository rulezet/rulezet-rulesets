rule sha512_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="76b8852416bb7691d0649e0fafe3332549352f9f158c81801ddcd39eee750565fbc966185d10c011e21a26ac5c50f804319eb82a08f74d78127fbda2de80f9c5"
    $a2="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="ce2a429a1c79d4068c0c7e54f5500ce16285d85730cb9ec0b61240f88ef9c870292200a1c069bd57d5e092874567058c91782513763bc30d86fedca63820c482"
    $a5="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a6="ce2a429a1c79d4068c0c7e54f5500ce16285d85730cb9ec0b61240f88ef9c870292200a1c069bd57d5e092874567058c91782513763bc30d86fedca63820c482"
    $a7="f6fa8f685a4fc06ee33cb5824faec8d994ee2875db645012304b8f23e01aad73ca7ee9fb29bff06e8ce856ae9c3f49f3e58b3edbd7009493f72be079d0ba03c3"
    $a8="ce2a429a1c79d4068c0c7e54f5500ce16285d85730cb9ec0b61240f88ef9c870292200a1c069bd57d5e092874567058c91782513763bc30d86fedca63820c482"
    $a9="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
    $a10="ce2a429a1c79d4068c0c7e54f5500ce16285d85730cb9ec0b61240f88ef9c870292200a1c069bd57d5e092874567058c91782513763bc30d86fedca63820c482"
    $a11="1304483a68eea9166fb01a6d68ba76aedf956217153fc8a9f323f6376b57e205934062a1c9d03fc9a56f9abf8dd1ec96d4eb0977c6675e9b506f902fb5473776"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}