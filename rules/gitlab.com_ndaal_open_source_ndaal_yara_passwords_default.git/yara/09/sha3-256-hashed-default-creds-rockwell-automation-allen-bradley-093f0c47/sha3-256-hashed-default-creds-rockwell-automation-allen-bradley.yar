rule sha3_256_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a2="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="ea2dd0bafaba2169f517e8f3edc182c67637b89903c69c68c86eb386b8cb7101"
    $a5="4d614f42f26e33094907a4f514089b6fbe39406819596e72cc0a6c9e3a19d853"
    $a6="ea2dd0bafaba2169f517e8f3edc182c67637b89903c69c68c86eb386b8cb7101"
    $a7="9f0b1265514403b23ba0c75f5345a55981601bb2b735eecae81a3fc3bbeae23b"
    $a8="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a9="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a10="a8bb0b0a4db037a2056889667e0672b4d4dbc6fff045408e13efd377cdf034b3"
    $a11="bdb3f8add40dad8b96492731a523f85358d8f3c3ec6458ba9c3aeb02fe8d48ab"
    $a12="2f6c7a4002c96b6bfb5b6cf9249ca5caebca87e292d5af0e14f125a1f73d1862"
    $a13="bdb3f8add40dad8b96492731a523f85358d8f3c3ec6458ba9c3aeb02fe8d48ab"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}