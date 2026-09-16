rule blake2s_hashed_default_creds_sierra_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sierra_wireless."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a076a699190673026fe44f7b523d321fcae79e70945007bdb1c86295a11c4135"
    $a1="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a2="a076a699190673026fe44f7b523d321fcae79e70945007bdb1c86295a11c4135"
    $a3="fdd24509455b06322493dd4eb221d4b78b27eac95fbb19aba9c22ac7fbdc3946"
    $a4="a076a699190673026fe44f7b523d321fcae79e70945007bdb1c86295a11c4135"
    $a5="bb03c487b908d80b317bbbb78b0deb4328f5cf04d027e6768bd8854eae478bc7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}