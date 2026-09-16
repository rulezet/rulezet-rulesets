rule PK_UPS_z0n51 : UPS
{
    meta:
        description = "Phishing Kit impersonating UPS"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-08-15"
        comment = "Phishing Kit - UPS - 'Z0N51'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "clients"
        $spec_dir2 = "inacho"
                $spec_file = "q.png"
        $spec_file2 = "helpers.css"
        $spec_file3 = "sms.php"
        $spec_file4 = "defender.php"
        $spec_file5 = "mobilemenu-fr.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}