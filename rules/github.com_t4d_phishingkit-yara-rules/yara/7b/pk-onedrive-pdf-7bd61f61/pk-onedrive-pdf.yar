rule PK_OneDrive_pdf : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-15"
        comment = "Phishing Kit - OneDrive"
    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "images"
                $spec_file = "error.php"
        $spec_file2 = "connected.php"
        $spec_file3 = "geoplugin.class.php"
	    $spec_file4 = "pdf.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_dir and 
        $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_file4
}