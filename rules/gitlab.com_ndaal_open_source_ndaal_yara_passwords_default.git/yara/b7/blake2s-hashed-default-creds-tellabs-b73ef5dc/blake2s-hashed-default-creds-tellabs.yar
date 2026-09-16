rule blake2s_hashed_default_creds_tellabs
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tellabs."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="677c0e1c8b881a4688b8c5408d7ca3761b0645652e9a7b40b855b80c5e6b501c"
    $a1="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a2="e20bdfecc0ab442df3491a771ededf5b8ec5c04e012019ab92b1aa1e12ed3d62"
    $a3="7ff965229dd79bf1fe3f663af4ffe50b247b0df3014b13f179ecdf8d2e675510"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}