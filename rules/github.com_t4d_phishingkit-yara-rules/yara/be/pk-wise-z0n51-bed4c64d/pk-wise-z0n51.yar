rule PK_Wise_z0n51 : Wise
{
    meta:
        description = "Phishing Kit impersonating Wise.com"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-07-18"
        comment = "Phishing Kit - Wise.com - 'Main Author: Z0N51'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "auth"
        $spec_dir2 = "xN9dG1"
                $spec_file = "BrowserDetection.php"
        $spec_file2 = "app.php"
        $spec_file3 = "anti8.php"
        $spec_file4 = "app.webp"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}