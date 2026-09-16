rule sha3_384_hashed_default_creds_solarwinds
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for solarwinds."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b53235ee3471c33bf9b050c016144806618d351223a389a2b4a0494cb4600d4bc746cda2dd2f385c83654bba2f8384c"
    $a1="b3607f234dd465cbf913198e1e6afc6d4b1b18f058c57f50c031fbfef8eea8126bdd5a16b75ed022e753d323186c371c"
    $a2="a09edc6cdd0e17a66a842e962e8d034bfb66feb6cd9e3d5d98e004b672197111745d65aaf37dd2aef626127055829fb9"
    $a3="a09edc6cdd0e17a66a842e962e8d034bfb66feb6cd9e3d5d98e004b672197111745d65aaf37dd2aef626127055829fb9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}