rule sha3_384_hashed_default_creds_galacticomm
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for galacticomm."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="167f8244658367ae1d587fdd792555edfbdbc38dc99e1802d835d55dccd33d8cc051817ce39d1907e60791adb21dff54"
    $a1="167f8244658367ae1d587fdd792555edfbdbc38dc99e1802d835d55dccd33d8cc051817ce39d1907e60791adb21dff54"
condition:
    ($a0 and $a1)
}