rule sha384_hashed_default_creds_tasman
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tasman."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5fd6937ab0f465e4586d60c7a263f543e642e2f5153dc747643bfbf6d674c2da2413342f2b3af94283270bf2e33168aa"
    $a1="cb0d861c8af5784a7a79ccb114744ad728f567e744c9480ad90e0ef1be2ee9eaad18fb3e65d657b6286d7ae221738cd9"
condition:
    ($a0 and $a1)
}