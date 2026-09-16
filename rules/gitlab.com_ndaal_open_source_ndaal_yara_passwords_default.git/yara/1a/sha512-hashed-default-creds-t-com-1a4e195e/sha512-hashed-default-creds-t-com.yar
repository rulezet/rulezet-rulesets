rule sha512_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d8dffa78639cd41e5b3fb86b5953374babb75b429f83cc2052d653212972f969ca9cc45dc9833e7a97cfd4457ad09249dc607bbc09d315b33fa5ba556639822f"
    $a1="3d409d00b4f1463d40af7a9076cc03f1f427a8e5e4b04fe5bb386ce7d0aa3725d809b7135383d9a9432ba5c3debfc40f2699a1ddb510711e5de06ba6d55215a6"
condition:
    ($a0 and $a1)
}