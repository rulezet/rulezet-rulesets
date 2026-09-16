rule PK_OneDrive_jeff : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-05-23"
        comment = "Phishing Kit - OneDrive"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "jeff2.php"
        $spec_file2 = "index3.php"
        $spec_file3 = "microsoft.css"
	    $spec_file4 = "other.html"
        $spec_file5 = "jeff.php"
        $spec_file6 = "office.php"
        $spec_file7 = "index.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and 
        all of ($spec_file*)
}