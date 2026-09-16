rule PK_Nickel_tahma9 : Nickel
{
    meta:
        description = "Phishing Kit impersonating Nickel"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-10"
        comment = "Phishing Kit - Nickel - 'TG bot name tahma9_bot'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "clients"
        $spec_dir2 = "fucked"
                $spec_file = "auth.php"
        $spec_file2 = "c94c03d8.png"
        $spec_file3 = "informations.php"
        $spec_file4 = "sms.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}