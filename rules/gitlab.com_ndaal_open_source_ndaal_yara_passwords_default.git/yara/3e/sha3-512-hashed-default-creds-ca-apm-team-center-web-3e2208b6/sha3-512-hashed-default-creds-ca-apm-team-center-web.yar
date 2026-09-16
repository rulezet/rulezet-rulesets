rule sha3_512_hashed_default_creds_ca_apm_team_center_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_apm_team_center_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90f2e09d2bbcaec0bf162a060461aa3f49647fec9cd87f0df9ea028e723ce3723fd47026b152f9fadf7af211cec81c285b8223199bce57ceb7aeafa60752a100"
    $a1="90f2e09d2bbcaec0bf162a060461aa3f49647fec9cd87f0df9ea028e723ce3723fd47026b152f9fadf7af211cec81c285b8223199bce57ceb7aeafa60752a100"
condition:
    ($a0 and $a1)
}