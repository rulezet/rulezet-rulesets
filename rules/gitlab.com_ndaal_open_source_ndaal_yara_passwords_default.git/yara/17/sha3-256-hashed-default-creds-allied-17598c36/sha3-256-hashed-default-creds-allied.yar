rule sha3_256_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d582e49e6418298578ef5d896b08ac121fff042ea7f8ed13fdafa7453f5c389d"
    $a1="97418e93d514bfe7a5e1ffb7fbfa520340db0ae37a8238c1b4c4e9ec13fbff51"
    $a2="905d922e19eb59c39a963226f7efd9f36666accc1cc08fc2940da0216ecbf4d2"
    $a3="905d922e19eb59c39a963226f7efd9f36666accc1cc08fc2940da0216ecbf4d2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}