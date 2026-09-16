rule sha3_384_hashed_default_creds_hosting_controller
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hosting_controller."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1c17b444da39eb31fa36dbcfc23d38d1ac776dc59e042d99be888b766242ff4b79dce5552772f3782529446e4dae45a2"
    $a1="d61c638a0091dea10873164acaa9a2d8efd3efe7fb340bcb73a2a17efa72843fdd44018e27f07e7302be4134f28ded53"
condition:
    ($a0 and $a1)
}