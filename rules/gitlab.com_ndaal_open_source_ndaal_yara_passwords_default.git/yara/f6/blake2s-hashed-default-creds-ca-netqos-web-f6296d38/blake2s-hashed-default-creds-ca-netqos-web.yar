rule blake2s_hashed_default_creds_ca_netqos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_netqos_web."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="20b76afeb2ba472287a9e663c13233559211cdb904639369d98ad2d0d48d1e41"
    $a1="01385c4d3f3038c1de7c5593409e9ac937c46a9ea9d376fda0c747b389451f32"
    $a2="20b76afeb2ba472287a9e663c13233559211cdb904639369d98ad2d0d48d1e41"
    $a3="67536e76f4557c75fc3e48f28d359b6e24c082c64f8aefa949717e1233e6e3b3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}