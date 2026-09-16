rule sha3_224_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a1="deaecd48a1f6a5dc5238e1f8d5012f425bd7c8b96ba7bbe08229820a"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="a2fcd96462d82e1cd53d6b2dba8fc00c31d68b15f50b0aebb5c99b13"
    $a5="a2fcd96462d82e1cd53d6b2dba8fc00c31d68b15f50b0aebb5c99b13"
    $a6="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a7="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a8="e810597249305f414f75eb5a9d2644820de439bc4647bbbdd90f702d"
    $a9="e810597249305f414f75eb5a9d2644820de439bc4647bbbdd90f702d"
    $a10="9b50c41c3d8dbc5749eea69cf13855e34c3a42601a53c6189cd80219"
    $a11="9b50c41c3d8dbc5749eea69cf13855e34c3a42601a53c6189cd80219"
    $a12="dd2ca5875d0b78d22778a554da348e9573c5d766eb758ac2caa4e9fc"
    $a13="d3dec77e80bb6f533414323b4dfd739941d4438cb099509b25e56ecd"
    $a14="901a6bbc8420c582476a5e532991e8ad2a6eb47f257e46e7ebce397b"
    $a15="901a6bbc8420c582476a5e532991e8ad2a6eb47f257e46e7ebce397b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}