rule sha3_512_hashed_default_creds_atlassian_confluence
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian_confluence."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0fc9b8b5112b269efd2e8e4ee649d8032c0187a98962f985e561b47e21183eeefe8222b38c846f995d0fc6b65a5abc1e55d4df0603ee5fc469f6af33069dd8ec"
    $a1="ae3cbd1e530268ca1c6bc13aebbdb0dd95323ca521efcabddd40147bbd1ad4f844e1d53006a976ebd2bce62f0036ed3bcc4909bef47e101cfda6cdc248d6a9bb"
condition:
    ($a0 and $a1)
}