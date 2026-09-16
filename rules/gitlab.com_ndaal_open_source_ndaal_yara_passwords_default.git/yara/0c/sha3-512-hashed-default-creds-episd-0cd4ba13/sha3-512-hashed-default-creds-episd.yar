rule sha3_512_hashed_default_creds_episd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for episd."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c6e84f348796b56cb8d9fe545549e509aa37e6cc3d0d2ba3c72255c76874b0520532bdc9961facf0fc3fba972310736e0accb0890ab041a5f32665f8aede7317"
    $a1="3716d757f739c14ea17a89ee7ec9a73ab3e54674b885e717064591986fb8cee9eeb48f07f60df3ca48c2a81b1bddc242388d2d8069f13600ec91b30942e5d89f"
condition:
    ($a0 and $a1)
}