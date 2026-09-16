rule nthash_hashed_default_creds_gossamer_threads_inc
{
    meta:
        id = "3RbG2aU5nMUPc7UgIFWm2V"
        fingerprint = "875ee12bbb08afb5457325cd552ef4995d9caedeaa4f1f4c84819cbcadfa82bb"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gossamer_threads_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="dab0d9d3d7da0c32e595a1c554a8493b"
    $a3="dab0d9d3d7da0c32e595a1c554a8493b"
    $a4="823893adfad2cda6e1a414f3ebdf58f7"
    $a5="823893adfad2cda6e1a414f3ebdf58f7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}