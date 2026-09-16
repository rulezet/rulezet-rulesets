rule PK_A1_webmail : A1
{
    meta:
        description = "Phishing Kit impersonating A1.net webmail "
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-12"
        comment = "Phishing Kit - A1.net - 'Anmelden - Webmail 7.0'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "anmelden-Dateien"
                $spec_file = "anmelden.php"
        $spec_file2 = "id.php"
        $spec_file3 = "logind.php"
        $spec_file4 = "login-logo.png"
        $spec_file5 = "anmelden.htm"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}