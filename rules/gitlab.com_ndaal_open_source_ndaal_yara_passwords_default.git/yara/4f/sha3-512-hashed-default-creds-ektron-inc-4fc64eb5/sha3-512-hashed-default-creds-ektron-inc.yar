rule sha3_512_hashed_default_creds_ektron_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ektron_inc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4f53bad004878396e755bea0549c17c8853efe0da2b2cd8dc2a3313906dec8c596a73f7eeb8873af8795ef17df303a862cea7330b5ec823246437ae314796156"
    $a1="4f53bad004878396e755bea0549c17c8853efe0da2b2cd8dc2a3313906dec8c596a73f7eeb8873af8795ef17df303a862cea7330b5ec823246437ae314796156"
    $a2="c8aeaaaf3ba4cf140fb8abeaa7743374d338ab00fd4bacf642ee324baf75db6eb5d9ec0ce0dd5e4d6b9ef030fadf5f4dce6b8597d1e350c4cd766a98cf37546d"
    $a3="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}