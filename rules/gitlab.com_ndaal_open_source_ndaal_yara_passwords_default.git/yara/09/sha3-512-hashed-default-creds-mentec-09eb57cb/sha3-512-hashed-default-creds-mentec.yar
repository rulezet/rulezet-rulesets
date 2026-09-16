rule sha3_512_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2091216f5c8bfc962206f9135031bc011f3831f3651b1827c20357f238312fedd50d3a05a4a62fb8a1afc8847a38f0912bcec151c5a2a2e1f4552911a80ca46c"
    $a1="7e522d39b21fa3d9b17108f158549cbe0761480df202ea73f3579c0751a9f7fe52b7c3d7cce6ff0604a33e85df3634b179d2fe665f131827602ef837e663aa27"
condition:
    ($a0 and $a1)
}