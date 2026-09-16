rule sha3_384_hashed_default_creds_voicegenie_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for voicegenie_technologies."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a44b8e3acfe7b0bab875a6775a80d564c959a7904a10e7ffe08e37e209eba708ab48e5303d271b34ae9e3bef82082d40"
    $a1="a44b8e3acfe7b0bab875a6775a80d564c959a7904a10e7ffe08e37e209eba708ab48e5303d271b34ae9e3bef82082d40"
condition:
    ($a0 and $a1)
}