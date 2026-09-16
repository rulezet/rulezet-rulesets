rule blake2b_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43886c4979efcf7990b5283dc2826b5d7247407adf002b3a95f6b04ebf5e483fe3ed435c8ba731492f0cc99c7af8221917e720d6ab41c8ce7f6afcc91392c159"
    $a1="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="ef2fd09f1a0711ffb157269b5f22c433a85a2f3396d8d9348ad9564ea7a6bd425026558c84725e288b9eea12002305558cd95e61fe7a198d1bb69df986c1b3d3"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="8d2f4f0bac20160beccfa32131beeb745b19fa24352e74356659edf6e463847b91130101ef25bf20d2cd8bb46a5b3558f5fe28361c15ca6e6513160d569c9592"
    $a7="432202ebdb99b29e5ae78eb00f46d3522a0234d765b2fb0a32181ef6b79f3a4e2cb2ee8c6bb188fbacc19f2eaa6037b5da8165f699ba5209d104e2bafc9cc392"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}