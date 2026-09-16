rule sha3_512_hashed_default_creds_jaspersoft_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jaspersoft_corporation."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a9210a3b1268ce3f2d9b5357dc79c1a4902cb5c5d7244589990263f1bac3d2678854031cc70444921fc6fb11ff9568dabc41a48b6bf3b808e84be58c0df4a881"
    $a1="a9210a3b1268ce3f2d9b5357dc79c1a4902cb5c5d7244589990263f1bac3d2678854031cc70444921fc6fb11ff9568dabc41a48b6bf3b808e84be58c0df4a881"
    $a2="a385c6bbd5db87818fc98653dc5ceeb45dbcc9eb831f4cf15af5583c3f3ab27300cc640a001602b136fa416d0a0b285ea81eb9575b468fdfaa0d5a23c3905c77"
    $a3="a385c6bbd5db87818fc98653dc5ceeb45dbcc9eb831f4cf15af5583c3f3ab27300cc640a001602b136fa416d0a0b285ea81eb9575b468fdfaa0d5a23c3905c77"
    $a4="370f0db03538cdfb4f230f1338131ef212179b7473e4ba53860487c0f2a8e470a95bd1bab15aac2f4f3d9e70263b79d353aec6840fbd5b93c248983d856ca7b2"
    $a5="370f0db03538cdfb4f230f1338131ef212179b7473e4ba53860487c0f2a8e470a95bd1bab15aac2f4f3d9e70263b79d353aec6840fbd5b93c248983d856ca7b2"
    $a6="8ca722b033b8e0f65c3373879389c8265599889ba6ff331528f1543a804cd2a1692573b0a09be80e70f7ed8a49958cc2da2d04cde5d0d3d0ac56dc246aa05481"
    $a7="8ca722b033b8e0f65c3373879389c8265599889ba6ff331528f1543a804cd2a1692573b0a09be80e70f7ed8a49958cc2da2d04cde5d0d3d0ac56dc246aa05481"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}