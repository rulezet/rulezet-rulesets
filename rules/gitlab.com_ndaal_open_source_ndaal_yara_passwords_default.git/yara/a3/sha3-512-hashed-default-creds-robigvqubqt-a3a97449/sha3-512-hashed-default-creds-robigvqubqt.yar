rule sha3_512_hashed_default_creds_robigvqubqt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for robigvqubqt."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="42f9d2be50b77df4abbbff945ab81540aefeb7da5ef278eb4aa0670e2334197f13b0604bd1e3a3f5d976dad30854c88028dd76668ec55d3ef73c0a33c121165d"
    $a1="2fa1455c1bc4b16b04055b0b59f0cd2d8cb61b30d0f94fcc8fcae2b387f5629cdea8e730ce944b585cfa5a9adaf137f6f698b6570618ae37fa7b3ad0cf441703"
condition:
    ($a0 and $a1)
}