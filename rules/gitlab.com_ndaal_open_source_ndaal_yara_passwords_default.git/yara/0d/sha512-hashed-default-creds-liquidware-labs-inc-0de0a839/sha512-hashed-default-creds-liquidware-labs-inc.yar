rule sha512_hashed_default_creds_liquidware_labs_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liquidware_labs_inc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="026cbed7b25e63a97c4a2509b9ec77ab49b181fc1053eeb3d4a95d87aef057dfbfe40d968c14e8b6590544a53652c0ab37a10de0679581dada3b1d1a4f21a545"
    $a1="cb3234ebe5f89ce313284062ca63fb3d3a463d16cebc1bebdaba9ceb4e57fa35d87e195db50f41b4f2344b4f38cfc802defd4706c81a023cad2026a936e62edc"
condition:
    ($a0 and $a1)
}