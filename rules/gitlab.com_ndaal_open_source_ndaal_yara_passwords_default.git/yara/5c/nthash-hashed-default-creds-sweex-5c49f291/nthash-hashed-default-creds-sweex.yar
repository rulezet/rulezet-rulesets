rule nthash_hashed_default_creds_sweex
{
    meta:
        id = "6w1QAUfxIzKMCDgRlgpLxG"
        fingerprint = "2e96eb9662f8111c37cc363b14ce146c1835bb3963cca8996adc07397d407998"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="28fd0495591d27493ceb953b0cc90dc3"
    $a1="66bff22ef634404b65bf0ec421a8bb1a"
    $a2="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="c130686c5e7390f6dfb455744d6ca639"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="93834cb9d11de401604c62928f8fdc16"
    $a7="93834cb9d11de401604c62928f8fdc16"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}