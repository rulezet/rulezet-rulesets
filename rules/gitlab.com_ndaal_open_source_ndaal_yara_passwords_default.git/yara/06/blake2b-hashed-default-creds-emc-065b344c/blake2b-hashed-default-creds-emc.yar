rule blake2b_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bc8653499aba9b909eecec568e20a1855cfc87f30ef8e109ef4e6d4cb9fff8aa9461d5c3092fb1e5f3950ca5fdf986cc52927a2b1d7bb30af201f2ff95f34d42"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="478cc3bbbddedb27bab8d1b670a86380f92a53e33f9637e27ec4fe67bd093f7749f2a4f7fc77b0490dd2507433c982829ae8814cc89014a3ec1df5064fa04536"
    $a3="009f143028d34d1f7f79c6c674faa58d9b0b33fc31b78b6b560b5c8dc953f1a7175e87d8d01fa107da3d534062904d7e3356464497ed7b43419fa2ceee348a6c"
    $a4="2ae6a28c0d3ebc14e236bc9c21f70a7ce2830dd3c28f536d342888244e780e3bd14e38abbe59c18827a60175c5bd52f4cd82c2f0816587cb6ba63b9fafa6558a"
    $a5="80aa441595cdb25275c04da116a500a6ddd59d36dee7b6a41e2f9aa7ce86727e90037b3b4234d9c357981c2620958886226157b50ad94f5cc9b21bf8cb46ca93"
    $a6="bc8653499aba9b909eecec568e20a1855cfc87f30ef8e109ef4e6d4cb9fff8aa9461d5c3092fb1e5f3950ca5fdf986cc52927a2b1d7bb30af201f2ff95f34d42"
    $a7="9be0382b6dae8d7f2936b96bb74d1999750af836734d7128d62554f42d3f5c4d77e35a5d95d95d0e141ff43d976080d2de2dc01f7ebb3fb9daea374f841cd83c"
    $a8="06bac88d56ef044ec6be1ccb3d7cbaf60d76b43aac94a5758c4d0dd4065e9298daaec1ea422fc508e08ad46f91cce3ab51846b5ff3335c4eb2b32faa4da3afa6"
    $a9="71db035183bc0c08edc1865b71832435ffa333ddb7b2b28b35e011f31de4f3a7a3c5b2a1e248af7689a59f4ba91795d67cd700d9dbd29ba7331226f8dda30329"
    $a10="62340171752901228fc3cc903f2ffbe634b64e2fbeb19556e9564e24e86fc24969344e04069c25204b3a492ff0cfa0c92d75082a47d29ba09d87d03f064a5658"
    $a11="e23f3df559069a8c34e5fa474aeedd701d32f3a25ba01ccdb9de5575045e9fdd0dbf6172a2d31c7a57cd110bd6baf210c5f344b3de701f5c95cfe7c070a12f57"
    $a12="871bfc6c0bd0e35c2dc9c289a3f3966437644869fc781c494bf88aba4b1aa5d98a36bb6b29e2cb14807176c1a80f5a0e4550f795421da6a6e07971d6e98397a8"
    $a13="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a14="bc8653499aba9b909eecec568e20a1855cfc87f30ef8e109ef4e6d4cb9fff8aa9461d5c3092fb1e5f3950ca5fdf986cc52927a2b1d7bb30af201f2ff95f34d42"
    $a15="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a16="bca4107957a8ba8de3402bf54643d01b3e30794db6a347c54bc4cf65abcdfccb62116b23ba9406419133c4f86b8c62c71ef683487e2bf16410b2555eeae6a1ea"
    $a17="b622c98d488ee11d924919e2f44bdf287aa6b086b2855e3e2626a03f2d44f3f4daa3cd08de5507f92d0eb4d1ecf04e3e3659ee0a9deb7e8f0a03643331584ce0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}