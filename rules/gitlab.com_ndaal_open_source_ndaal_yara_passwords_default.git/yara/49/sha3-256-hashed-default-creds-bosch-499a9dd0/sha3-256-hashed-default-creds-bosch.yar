rule sha3_256_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="63e5b5a4137cfa77cb9d10adae081d0df082a826d8441721460d5933f5800056"
    $a1="63e5b5a4137cfa77cb9d10adae081d0df082a826d8441721460d5933f5800056"
    $a2="c1d8ee2b15adbbb220ee2fcb332c02b40b614e9e8fe788cdb0932c9ebbf76833"
    $a3="c1d8ee2b15adbbb220ee2fcb332c02b40b614e9e8fe788cdb0932c9ebbf76833"
    $a4="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a5="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}