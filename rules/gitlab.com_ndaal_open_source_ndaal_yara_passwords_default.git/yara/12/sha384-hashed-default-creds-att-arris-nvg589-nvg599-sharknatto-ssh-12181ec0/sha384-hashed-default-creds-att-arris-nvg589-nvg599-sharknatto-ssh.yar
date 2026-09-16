rule sha384_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="27cdcc8448efee8b04ec7bb58d4b50db619dfc4166e349f5f86932307cf031aca8f10a5e7e8543efd7e58a3140606283"
    $a1="a394d56e5cfd14a2d872e70e2f61aed1a572b3e706afd3eb9e65e4d3008ef5a2464066a12960343634ba7a9fffe456d9"
condition:
    ($a0 and $a1)
}