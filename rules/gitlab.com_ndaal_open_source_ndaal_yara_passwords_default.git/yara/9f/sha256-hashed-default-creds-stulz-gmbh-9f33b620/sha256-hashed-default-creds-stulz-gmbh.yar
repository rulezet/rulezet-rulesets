rule sha256_hashed_default_creds_stulz_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stulz_gmbh."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c83035054bb69a60d02e46ce4232ba32f4980fe5607d2ce314d04d682a3a5914"
    $a1="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a2="b7dab4d82976781363710f48e29ddb3a6f8add69029ed7f3d49b8b047c813e87"
    $a3="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a4="4737a15e2c762fa0758b8723c88dcb8af130ba8a5d3ee7c2a594404f7c9e770a"
    $a5="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}