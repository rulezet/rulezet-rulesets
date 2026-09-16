rule ldap_sha1_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}hgXE8qiVZU85JBbjQ9xgDXo4OW8="
    $a1="{SHA}hgXE8qiVZU85JBbjQ9xgDXo4OW8="
    $a2="{SHA}LaC2jfiEF1K7dHp2eAZ5vNh8YhU="
    $a3="{SHA}LaC2jfiEF1K7dHp2eAZ5vNh8YhU="
    $a4="{SHA}LIu9Tro7dNkK19nNi2XyVLwNe1Q="
    $a5="{SHA}LIu9Tro7dNkK19nNi2XyVLwNe1Q="
    $a6="{SHA}qb16W1g8vgguLIUFlccaaBhibxA="
    $a7="{SHA}qb16W1g8vgguLIUFlccaaBhibxA="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}