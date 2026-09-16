rule PK_LaPoste_ard8no : LaPoste
{
    meta:
        description = "Phishing Kit impersonating La Poste FR"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-08"
        comment = "Phishing Kit - LaPoste - 'ard8no das'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "verification"
        $spec_dir2 = "antibot________GHAYT___ZONE"
                $spec_file = "config.php"
        $spec_file2 = "loading-sms.php"
        $spec_file3 = "infos.php"
        $spec_file4 = "logo-app-laposte-mobile-new.png"
        $spec_file5 = "app-laposte.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}