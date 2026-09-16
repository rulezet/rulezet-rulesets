rule sha3_512_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ae30ea303bad8626c29abbf3932ff11d9f8999d028d5cca978a85eb7e9ff4226d1f7e78ec0d9959ac88b412f0dac7022ee9e036ce05f5a845c9c4711b4a7139"
    $a1="a385c6bbd5db87818fc98653dc5ceeb45dbcc9eb831f4cf15af5583c3f3ab27300cc640a001602b136fa416d0a0b285ea81eb9575b468fdfaa0d5a23c3905c77"
    $a2="a385c6bbd5db87818fc98653dc5ceeb45dbcc9eb831f4cf15af5583c3f3ab27300cc640a001602b136fa416d0a0b285ea81eb9575b468fdfaa0d5a23c3905c77"
    $a3="a385c6bbd5db87818fc98653dc5ceeb45dbcc9eb831f4cf15af5583c3f3ab27300cc640a001602b136fa416d0a0b285ea81eb9575b468fdfaa0d5a23c3905c77"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}