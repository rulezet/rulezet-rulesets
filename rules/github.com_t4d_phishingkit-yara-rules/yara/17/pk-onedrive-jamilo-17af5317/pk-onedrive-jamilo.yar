rule PK_OneDrive_jamilo : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-09-27"
        comment = "Phishing Kit - OneDrive - 'Created BY JaMiLo'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "asd"
                $spec_file = "pdf_error.php"
        $spec_file2 = "securepassword.php"
        $spec_file3 = "busy.php"
	    $spec_file4 = "fixed.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_dir and 
        $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_file4
}