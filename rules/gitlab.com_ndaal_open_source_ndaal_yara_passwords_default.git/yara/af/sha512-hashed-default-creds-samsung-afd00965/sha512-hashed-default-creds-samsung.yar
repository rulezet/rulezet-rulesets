rule sha512_hashed_default_creds_samsung
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samsung."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1cef2b349483969b9be871f1b14536a272050e66acdbc1f23894946bed7ae9bf2f54cbf4d64ac3cc62b0c6d1c6a638a22cf98c0cf3b85992cee242323612308c"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="d32997e9747b65a3ecf65b82533a4c843c4e16dd30cf371e8c81ab60a341de00051da422d41ff29c55695f233a1e06fac8b79aeb0a4d91ae5d3d18c8e09b8c73"
    $a3="d32997e9747b65a3ecf65b82533a4c843c4e16dd30cf371e8c81ab60a341de00051da422d41ff29c55695f233a1e06fac8b79aeb0a4d91ae5d3d18c8e09b8c73"
    $a4="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="1c3b0ec0868e7aab02015be0fb32cc6ef548b75db78b08c8b643dc152e7efc729d76a68bee607c3639750ba854f0ef9bff227eb97094378c12ad3967ca23f446"
    $a7="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}