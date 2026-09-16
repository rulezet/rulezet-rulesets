rule blake2b_hashed_default_creds_fastwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fastwire."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ffa8a10c6c548458f60e567eb13900ff18ef6471655ace0c325b391812210c5a21cec1ec3f3dea62163fcf82eefdfcc0f025ddf695f8c720eb423c495caf78b0"
    $a1="176cbb618d6875e597a7fa5e209b1d6ee4074ee899efc6abf3f797435e1067042e3c670016f3fcfe26232ef30dee6dfbd0765e4a162947d0c1a8de329b9a24ff"
condition:
    ($a0 and $a1)
}