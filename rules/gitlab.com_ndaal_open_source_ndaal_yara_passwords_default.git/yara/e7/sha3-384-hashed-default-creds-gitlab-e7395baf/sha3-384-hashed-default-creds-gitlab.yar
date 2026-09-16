rule sha3_384_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1137f2dddf0376c98baf89b13bd4f659bf2b4b5a82efcf75efefdda10f385a63d7501b98d87a0edde0a38e5559acc859"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="1137f2dddf0376c98baf89b13bd4f659bf2b4b5a82efcf75efefdda10f385a63d7501b98d87a0edde0a38e5559acc859"
    $a3="14b1914cf42ec57ecd7f56c7d6fc406cfbd67e5f1028f4e72bf1f665bbb359f60931835b2ba21ec2d6d6008d7fe7cb4f"
    $a4="1137f2dddf0376c98baf89b13bd4f659bf2b4b5a82efcf75efefdda10f385a63d7501b98d87a0edde0a38e5559acc859"
    $a5="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}