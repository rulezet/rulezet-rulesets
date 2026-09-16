rule sha512_hashed_default_creds_cyberguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberguard."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4af4b2778016485290c3a133986c08e30b2cd96ef70bc68a4add3c804fb58f652663c5ca863f03fb1d11c644b9a81a1c0bf998ff40702bbfd6c48c4e49380434"
    $a1="4af4b2778016485290c3a133986c08e30b2cd96ef70bc68a4add3c804fb58f652663c5ca863f03fb1d11c644b9a81a1c0bf998ff40702bbfd6c48c4e49380434"
condition:
    ($a0 and $a1)
}