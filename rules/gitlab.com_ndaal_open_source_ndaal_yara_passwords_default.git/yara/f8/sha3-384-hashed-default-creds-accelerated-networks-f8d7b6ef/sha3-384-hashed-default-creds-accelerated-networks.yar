rule sha3_384_hashed_default_creds_accelerated_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for accelerated_networks."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fa9b7db45076f001e63325202a93191aec6690f9028a9e063ff6b72d600dd8eb0414e35b7d5b0bcaee58062249fa3486"
    $a1="d438306fa611925107fb89a7248146a396c00ecc168a0b57d0ec64e8322d6efed561e206679f26411921844994d63fcb"
condition:
    ($a0 and $a1)
}