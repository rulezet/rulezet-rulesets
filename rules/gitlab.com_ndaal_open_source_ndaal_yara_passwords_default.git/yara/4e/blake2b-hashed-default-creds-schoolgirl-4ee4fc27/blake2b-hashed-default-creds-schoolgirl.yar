rule blake2b_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d38749b738890a960e3b46fe512e82e61827ec32aed422e1ca25655cb1298b005e255cab45e8eee64d66b87a313294d4d35b35dc5f90c89955d397540fdb550"
    $a1="506a74b9cb23fed6c4821f75e4cdf60e77520cbee30b5bfe7e675e6aaf2c78f2f90798463d18618dd520d89a3ee51d19ab3329078dc3e469ffffc372e9fb1269"
condition:
    ($a0 and $a1)
}