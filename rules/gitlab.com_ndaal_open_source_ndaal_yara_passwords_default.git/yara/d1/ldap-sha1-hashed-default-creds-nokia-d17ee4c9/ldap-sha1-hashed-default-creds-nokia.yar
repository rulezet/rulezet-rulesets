rule ldap_sha1_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}23CiD0A9rUOsvNwCkIYgedcwD34="
    $a1="{SHA}23CiD0A9rUOsvNwCkIYgedcwD34="
    $a2="{SHA}u/DgDc5CQElDP1rsHZMBPbNpgwM="
    $a3="{SHA}u/DgDc5CQElDP1rsHZMBPbNpgwM="
    $a4="{SHA}0qBNcTAaiRUhfdX6+B0Sz/1s2Vg="
    $a5="{SHA}0qBNcTAaiRUhfdX6+B0Sz/1s2Vg="
    $a6="{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ="
    $a7="{SHA}4ycjY/flnd7jxr4oEfYdTo+z8AI="
    $a8="{SHA}AeuE8FK6hX1hCiaBVijVM5OGyOk="
    $a9="{SHA}4ycjY/flnd7jxr4oEfYdTo+z8AI="
    $a10="{SHA}1h24NjXl9yBDPveKMPPLJp3wwNo="
    $a11="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a12="{SHA}wfRsgFIA2ACgwBhbMzNLJj00x+0="
    $a13="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a14="{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ="
    $a15="{SHA}/Tz8AoNIWLaEehi81ujowUX61Ic="
    $a16="{SHA}+bqYoGlK3gdAAX7yb3nvsQJgnHw="
    $a17="{SHA}+bqYoGlK3gdAAX7yb3nvsQJgnHw="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}