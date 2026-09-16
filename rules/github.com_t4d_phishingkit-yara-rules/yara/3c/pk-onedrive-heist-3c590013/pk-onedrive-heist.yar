rule PK_OneDrive_heist : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-03-15"
        comment = "Phishing Kit - OneDrive - 'From: /Heist-InMotion'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "cgi-bin"
                $spec_file = "next.php"
        $spec_file2 = "index.html"
        $spec_file3 = "1.html"
	    $spec_file4 = "1.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_dir and 
        all of ($spec_file*)
}