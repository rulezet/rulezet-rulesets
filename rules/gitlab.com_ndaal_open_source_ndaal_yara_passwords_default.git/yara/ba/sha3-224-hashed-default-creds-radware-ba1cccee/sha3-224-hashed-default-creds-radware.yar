rule sha3_224_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2470d6b818c2b7cf4b177929f3f5d8092307085d24aae6b77f634021"
    $a1="2470d6b818c2b7cf4b177929f3f5d8092307085d24aae6b77f634021"
    $a2="37a5be8930801a88da62fdcf696d09358fe48339010d2e10db5bd13b"
    $a3="37a5be8930801a88da62fdcf696d09358fe48339010d2e10db5bd13b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}