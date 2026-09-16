rule sha384_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2bf6a6403cf4db534d4475b623d954b47c94346205aa0dff368208c9bf17b2ea82adcd2de2b23817811784a94777379f"
    $a1="b6b91770b927e68ea6198bc4b53e9e722f24652580b3f4446588ebe3c7171c2dc49b3613f7134ef6b286c3cb14dde5f6"
condition:
    ($a0 and $a1)
}