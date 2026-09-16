rule PK_O365_Pus : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-02"
        comment = "Phishing Kit - O365 - 'Office Log Created by Pus..'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "run"
                $spec_file = "login-.php"
        $spec_file2 = "success.php"
        $spec_file3 = "system.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                $spec_file and
        $spec_file2 and 
        $spec_file3
}