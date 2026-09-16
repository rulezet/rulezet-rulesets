rule PK_FirstCitizenBank_prohqcker : FirstCitizenBank
{
    meta:
        description = "Phishing Kit impersonating First Citizen Bank"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-06-10"
        comment = "Phishing Kit - First Citizen Bank - '*Prohqcker*Telegram ID @prohqcker*'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
        $spec_dir2 = "img"
                $spec_file = "c.html"
        $spec_file2 = "personal.html"
        $spec_file3 = "prohqcker4.php"
        $spec_file4 = "theme-q2-c78f9a6334979dc02a4414cf3a8779e5.css"
        $spec_file5 = "otp.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}