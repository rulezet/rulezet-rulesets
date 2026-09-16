rule PK_WellsFargo_donflow : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-01"
        comment = "Phishing Kit - Wells Fargo - 'From: Donflow'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "+=wells+="
        $spec_dir2 = "system"
                $spec_file = "_+login=+.php"
        $spec_file2 = "sand_email.php"
        $spec_file3 = "Myaccount.php"
        $spec_file4 = "jquery.CardValidator.js"
        $spec_file5 = "send_carde.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}