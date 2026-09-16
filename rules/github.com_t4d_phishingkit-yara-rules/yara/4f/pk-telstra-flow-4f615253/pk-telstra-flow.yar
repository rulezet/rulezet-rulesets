rule PK_Telstra_flow : Telstra
{
    meta:
        description = "Phishing Kit impersonating Telstra"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-15"
        comment = "Phishing Kit - Telstra - using Flow.txt as exfil. file"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "src"
                $spec_file = "cc.php"
        $spec_file2 = "Email.php"
        $spec_file3 = "smserror.php"
        $spec_file4 = "1.svg"
        $spec_file5 = "pn-blue.png"
        $spec_file6 = "done.gif"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}