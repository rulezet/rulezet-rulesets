rule PK_NavyFederal_Hemsworth : NavyFederal
{
    meta:
        description = "Phishing Kit impersonating Navy Federal Credit Union"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-06-12"
        comment = "Phishing Kit - Navy Federal - 'Author = Mac Hemsworth"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Hemsworth"
        $spec_dir2 = "Send"
        $spec_dir3 = "File"
                $spec_file = "Relogin.php"
        $spec_file2 = "Account.php"
        $spec_file3 = "Anticonfig.ini"
        $spec_file4 = "useragent.dat"
        $spec_file5 = "Navy.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}