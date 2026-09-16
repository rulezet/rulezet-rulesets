rule sha3_384_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b0f9e5c2f7266a20e793bc00d82c28adc1ff5c3b903f81ec057cf6a613624b56e759fad9468aa16cf61d203179e54da"
    $a1="4c21117ec7e9dd46365ea0da5f068289c985f8c56f68b35870efe30878944aeffc18d29ca5bc804ae231191a8ef5ae9c"
condition:
    ($a0 and $a1)
}