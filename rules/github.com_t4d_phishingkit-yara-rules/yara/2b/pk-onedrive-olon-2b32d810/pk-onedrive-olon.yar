rule PK_OneDrive_olon : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-01-22"
        comment = "Phishing Kit - OneDrive - '|OLON H4CK3R|'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "o6"
                $spec_file = "odbfavicon.ico"
        $spec_file2 = "oneDrive.jpeg"
        $spec_file3 = "otherother.php"
	    $spec_file4 = "go.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_dir and 
        all of ($spec_file*)
}