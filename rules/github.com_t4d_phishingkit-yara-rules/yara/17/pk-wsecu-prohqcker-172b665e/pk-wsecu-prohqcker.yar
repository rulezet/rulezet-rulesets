rule PK_Wsecu_prohqcker : WSECU
{
    meta:
        description = "Phishing Kit impersonating WSECU, Washington State Employees Credit Union"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-07-12"
        comment = "Phishing Kit - WSECU - '*Prohqcker***WSECU***'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "WSECU"
        $spec_dir2 = "images"
                $spec_file = "c.html"
        $spec_file1 = "personal.html"
        $spec_file2 = "prohqcker4.php"
        $spec_file3 = "theme-wsecu-retail.css"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_dir*) and 
        all of ($spec_file*)
}