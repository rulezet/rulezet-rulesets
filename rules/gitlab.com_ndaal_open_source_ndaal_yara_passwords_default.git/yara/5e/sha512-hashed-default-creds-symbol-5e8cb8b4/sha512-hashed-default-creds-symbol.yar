rule sha512_hashed_default_creds_symbol
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symbol."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="60a8c2b8151f19e9906f9792c36fa2ff659dca4189bc2e7c82e830524e3c70813a8beee3a14f37321bd67abea79e9e8b12c445078c89344531a0452b7b1f632a"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="dc77a9990a0467e22c42be36697552e3e6b0891e4c758a864af94e621d62a6becbe7d388b255c3634c36ef09661c69ec4c7ad8ee1493cd8d925b2a4d4f040260"
    $a3="dc77a9990a0467e22c42be36697552e3e6b0891e4c758a864af94e621d62a6becbe7d388b255c3634c36ef09661c69ec4c7ad8ee1493cd8d925b2a4d4f040260"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}