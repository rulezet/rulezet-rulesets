rule sha512_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6e67f8dbbbe2b9b302250b570cb2099e0f937f7139544800e84719e545fc6bb3b6f21d1eba6ee7fc6737535b500a0bf3752c12015b4e80454ceeaf4ba08897f1"
    $a1="2a61ef940744863cce48f228bbe836f0689fdd32615064befbf7f70fb42464f5ad7a5f2121159ada672875d3199c3d02874399986a5d4d24527193a0684de372"
condition:
    ($a0 and $a1)
}