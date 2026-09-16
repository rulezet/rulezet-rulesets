rule mysql323_hashed_default_creds_dell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dell."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0b76a74f498d8f3e"
    $a1="67457e226a1a15bd"
    $a2="5d2e19393cc5ef67"
    $a3="43e9a4ab75570f5b"
    $a4="7f29029c5c1e5d43"
    $a5="67457e226a1a15bd"
    $a6="43e9a4ab75570f5b"
    $a7="43e9a4ab75570f5b"
    $a8="7825cd7a1880f574"
    $a9="58f7ee435f925abe"
    $a10="38d09abd3efe27ad"
    $a11="52dbd9061c1ca2d7"
    $a12="14d9d83627fcfc9f"
    $a13="67457e226a1a15bd"
    $a14="74ab8ba42bdff4d8"
    $a15="7e2536a525d52164"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}