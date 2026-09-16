rule PK_FedEx_finx : FedEx
{
    meta:
        description = "Phishing Kit impersonating FedEx IL"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-04-08"
        comment = "Phishing Kit - FedEx - 'RESULT BY Finx'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "action"
        $spec_dir2 = "killbot"
                $spec_file = "sms-sec.php"
        $spec_file2 = "settings.php"
        $spec_file3 = "forming-2.php"
        $spec_file4 = "test.css"
        $spec_file5 = "fx-favicon.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}