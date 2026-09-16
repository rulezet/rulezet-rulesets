rule sha512_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="37eeaab35694c370627464426956120b0eb8e6b8028ab8bb2779bedcc989cd1dd8f4b1d3f9167e50006a2473739977cc703867201f0f4f5bfb3e284a4f89b0af"
    $a1="37eeaab35694c370627464426956120b0eb8e6b8028ab8bb2779bedcc989cd1dd8f4b1d3f9167e50006a2473739977cc703867201f0f4f5bfb3e284a4f89b0af"
condition:
    ($a0 and $a1)
}