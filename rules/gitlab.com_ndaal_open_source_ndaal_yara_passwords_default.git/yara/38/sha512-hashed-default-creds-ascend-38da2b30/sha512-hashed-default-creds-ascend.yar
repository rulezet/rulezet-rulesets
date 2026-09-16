rule sha512_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="312f56286d241f48161a79d79da887d9a4c469e2656bba2f807a0fcb303f560a1f8d3ebc5ca35d375ceaa9419de273822a4c4f5d33b9dbad36a6bf1a74ae01fd"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="90009d12415ac46a2c7e4492c12bbbb22d7888011ca9aca98ac14837f210e110fc63b991f24f0d51dc4c18245e08cfd2d93380569ca3a00701dda743e9a08a69"
    $a3="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a4="bd41baa75fe7647f1d27c31a72b4e2dfc537db475e089a139f67a82d7f555aa1c902aab6ed849b376ff5fd0f2d37ea9f3421ec2ba2c82312c65806da7d45c648"
    $a5="ff3d9d060c06599e083d26bcdffd24b51c68e3a7cd10859d6763701e31dad0debdaee7085b95e7b0c5f9c535d5e031e75e885fde7a6056065fce009f597345c9"
    $a6="7bfb8ed4f69d24f6300c57f6bf8ec89f76e6d7158f09eaa4a1dad5128a153ab83e6e7248ca0bbc875494ba510e29fbc339cda3698a0ea414eea7eeb80f2bd283"
    $a7="837b64c137ec2633242b1363ab465707b6a26fecbd5c47e17a0ba457369afaaa9f04dda78a72d64607959a2a002586fdc77f87d943c95c42e7a9eca4ee2f41c6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}