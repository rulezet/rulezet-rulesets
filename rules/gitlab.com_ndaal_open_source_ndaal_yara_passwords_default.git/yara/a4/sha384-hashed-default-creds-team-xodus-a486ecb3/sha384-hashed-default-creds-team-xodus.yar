rule sha384_hashed_default_creds_team_xodus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for team_xodus."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="db3468813281f294730b7210c29fd2a1cdac962740a7d95c443a6f34c1613625ce065ba663c63a97c62fb9681964ffe1"
    $a1="db3468813281f294730b7210c29fd2a1cdac962740a7d95c443a6f34c1613625ce065ba663c63a97c62fb9681964ffe1"
condition:
    ($a0 and $a1)
}