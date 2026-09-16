rule sha3_512_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca618b265911ee80b3288cbd3c51281fc31d0e90432325e037c11b96ded04ccdad3dae2637c507f0a1b0e32d20ef8b37f0d97de4bb2ed9c506f512db2e09ecf"
    $a1="59f6d83edd3122738ea7c4d28ca71317419d790311f2664b44155b5d8bd2bfe36d932ef5cd99da1cd36dc34cfc19bedbcc2d17c2259eaddd2c1c55d77e14f86d"
condition:
    ($a0 and $a1)
}