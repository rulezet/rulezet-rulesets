rule sha512_hashed_default_creds_norstar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for norstar."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b432b0a9c70edec165669f331d0d035eed2296ede52ceaa43822c7666ea684fc05b8f80f29c904a415221ce1ea218a7a4e71a30fc10154004de5b67b7ce4e880"
    $a1="20670a420665c271eb91ace67038f49b64998b3b109aa8b180bdf3861dc1eb87f0c272f4bbccb6de642cbb2ed592a214a46d1044d67b8e7b7cbc5487546e5734"
    $a2="4ba64d882ad15628b03c4dc540c0fa632d6b265d0a0b3184e2d99087cf65e6f4fd1fd8ada5e864d80a692c14488e5857fec2296f7c235213b74e89c59bd8c5b7"
    $a3="80ba8241e014953e74f66be1c04fe0dbb59d8ef800fae9968dc59890e2f607bddb596087c0cfb9af150b28834b49c06412c6fcec2244ad6d2be213413a9aa1d8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}