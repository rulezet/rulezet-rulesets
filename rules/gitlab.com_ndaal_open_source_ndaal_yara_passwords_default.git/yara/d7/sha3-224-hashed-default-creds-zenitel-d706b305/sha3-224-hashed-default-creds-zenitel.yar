rule sha3_224_hashed_default_creds_zenitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zenitel."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="91c998d95dd632aff4f89ce2267bae3569aac0bc335cddd85442a337"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="df2099a205e965d2439f4d058e6d9ce0efab8761271f27cce682fd5f"
    $a3="cfbb56a314e406232e84144aa3b459691cc889b7b7d7406dcf2aeec1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}