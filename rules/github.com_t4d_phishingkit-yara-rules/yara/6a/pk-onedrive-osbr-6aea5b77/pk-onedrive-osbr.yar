rule PK_OneDrive_osbr : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-07-25"
        comment = "Phishing Kit - OneDrive - 'create an new instant of OS_BR class'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "images"
                $spec_file = "mail.php"
        $spec_file2 = "sync.php"
        $spec_file3 = "drive.php"
	    $spec_file4 = "0.jpg"
        $spec_file5 = "1.gif"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_dir and 
        all of ($spec_file*)
}