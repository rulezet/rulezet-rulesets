rule sha3_512_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1f7f20fd3bc86aa5b99df0efce3caecde11562f88db46cf59daca2d6b75085ff56667c32d35a820b82c55bb6ae52dc04c2e0ec4f9af72d132c4158ea56ba65d9"
    $a1="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a2="9ef64b874b753eb351b5788f0e16d2cddd3c35f77e67465d830ec1e8e47d16afcd86de0e2132d0fd58d93dd249a874c63dc518fdf6efc63f94d1e1beb7f8d8c1"
    $a3="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a4="b0e44564bad963a5b8fd84494303289fd068cb6bbdf14f5e70c2d2d20778c7be94a50cf79671add9f3c30354bda46461f9eba1e9934a9038cbc25c9d29b5822a"
    $a5="b0e44564bad963a5b8fd84494303289fd068cb6bbdf14f5e70c2d2d20778c7be94a50cf79671add9f3c30354bda46461f9eba1e9934a9038cbc25c9d29b5822a"
    $a6="01bf3a32baa45fd9dddcdb8b37c4983a4ac7ade9e753cf4373c64cbad34393c2718aa6685adff535922f983128aaa73ca19df4330f46392f2cb89d203bcbafbb"
    $a7="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}