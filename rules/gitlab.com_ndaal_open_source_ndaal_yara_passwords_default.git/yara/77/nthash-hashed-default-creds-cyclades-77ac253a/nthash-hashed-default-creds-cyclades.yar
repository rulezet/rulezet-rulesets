rule nthash_hashed_default_creds_cyclades
{
    meta:
        id = "4t1ZFdJNdtw5YKQ5YTpc93"
        fingerprint = "c9319a31419b4300da4c0686f1f788b4db3f152519ebd0d312ca75339224490c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyclades."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dc5ceb8becc02121fafbcc563daa54ca"
    $a1="fad2607eda55ca3ecf8d89067ee91f84"
    $a2="a94c9db11b77462c8956d761b4a92baf"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}