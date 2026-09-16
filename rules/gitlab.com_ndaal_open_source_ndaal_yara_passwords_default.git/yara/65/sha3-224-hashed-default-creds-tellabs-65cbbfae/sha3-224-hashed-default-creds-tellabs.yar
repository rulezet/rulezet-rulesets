rule sha3_224_hashed_default_creds_tellabs
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tellabs."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="11699ce18203656dff6ccebf5d653b40442d5c5b8e2275e7177558e4"
    $a1="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a2="32d9800b7c38b56625cd7939e35f030933685cc89b856898bd81760a"
    $a3="a7c1230f0e830d904dde62c173a576987afa7ee61d2789945c691b29"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}