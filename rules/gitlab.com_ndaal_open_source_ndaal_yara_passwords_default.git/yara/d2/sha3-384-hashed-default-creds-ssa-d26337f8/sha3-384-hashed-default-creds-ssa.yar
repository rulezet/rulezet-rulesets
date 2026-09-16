rule sha3_384_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8351f9f52ec352d4d182386e39ca40740290c6fe714b274d9f108764da5e722b40cd48de773a061c4ecffd6868558501"
    $a1="8351f9f52ec352d4d182386e39ca40740290c6fe714b274d9f108764da5e722b40cd48de773a061c4ecffd6868558501"
condition:
    ($a0 and $a1)
}