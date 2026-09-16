rule nthash_hashed_default_creds_voicegenie_technologies
{
    meta:
        id = "4lnVRqvUfn1FNks1h5mYSs"
        fingerprint = "1e8500833b8da372cae9177532ecab68a57eb3162184fcbec06a59367fd27dfa"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for voicegenie_technologies."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8cc19b6a8cfeac299c2871c86b38de28"
    $a1="8cc19b6a8cfeac299c2871c86b38de28"
condition:
    ($a0 and $a1)
}