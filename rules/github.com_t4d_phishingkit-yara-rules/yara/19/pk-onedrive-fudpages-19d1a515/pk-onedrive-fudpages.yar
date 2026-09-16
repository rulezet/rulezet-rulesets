rule PK_OneDrive_fudpages : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-19"
        comment = "Phishing Kit - OneDrive - 'FUDPAGES [.] RU'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "aol_files"
                $spec_file = "AA1.php"
        $spec_file2 = "GGC.php"
        $spec_file3 = "phone.php"
	    $spec_file4 = "YY1.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_dir and 
        all of ($spec_file*)
}