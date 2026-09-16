rule sha384_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="672737e7130b76016fd70da90a6335333abf04ea8307be4c8b0c5e3088f87d602dbec8b602480be4011cf4edaf449614"
    $a1="1feb54dd8d55fe3acdcc88bbefa920c7d57cbf14be8e12271c428cfa460e04f38caa37eef53f34c141dc1674a7967ba8"
condition:
    ($a0 and $a1)
}