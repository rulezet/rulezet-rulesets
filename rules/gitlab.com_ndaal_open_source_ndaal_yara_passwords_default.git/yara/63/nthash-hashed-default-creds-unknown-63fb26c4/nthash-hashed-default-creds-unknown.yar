rule nthash_hashed_default_creds_unknown
{
    meta:
        id = "5aCovpemOXFMpk7iqzMyza"
        fingerprint = "66dbd78b256262a4e3e5df6c388ce90de9b3256c7b93171eb8b30a4a3ec56d0a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="20fbb7d3552870a48725ccd3ef2f74b4"
    $a1="20fbb7d3552870a48725ccd3ef2f74b4"
    $a2="e337e31aa4c614b2895ad684a51156df"
    $a3="e337e31aa4c614b2895ad684a51156df"
    $a4="0cb6948805f797bf2a82807973b89537"
    $a5="0cb6948805f797bf2a82807973b89537"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}