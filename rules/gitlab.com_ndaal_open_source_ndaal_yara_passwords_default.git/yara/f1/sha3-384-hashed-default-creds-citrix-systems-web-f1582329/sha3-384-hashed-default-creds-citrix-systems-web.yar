rule sha3_384_hashed_default_creds_citrix_systems_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_web."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4a83d5df66225bc42aa9b38e4f811f52ea721eab29d061fa0abccabccdf98075de97720f5796bc86f2986a7161b2e80b"
    $a1="4a83d5df66225bc42aa9b38e4f811f52ea721eab29d061fa0abccabccdf98075de97720f5796bc86f2986a7161b2e80b"
    $a2="6f43dcbffa37b4eb4769c3ff6461afb8a8b8e20a3fc49f8741a0ef3a563eef3456886461cfff76a5fd0735f80888c9eb"
    $a3="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}