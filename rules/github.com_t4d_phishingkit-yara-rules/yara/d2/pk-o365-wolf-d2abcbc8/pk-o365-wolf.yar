rule PK_O365_wolf : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-05"
        comment = "Phishing Kit - O365 - 'Wolf-updated'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "script"
                $spec_file = "share-point.css"
        $spec_file2 = "throwit_first.php"
        $spec_file3 = "verificationAttempt.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                $spec_file and
        $spec_file2 and 
        $spec_file3
}