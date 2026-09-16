rule PK_OneDrive_ishuman : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-28"
        comment = "Phishing Kit - OneDrive - 'COOKIE[ishuman]'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "data"
                $spec_file = "rs.php"
        $spec_file2 = "email.php"
        $spec_file3 = "meta.php"
	    $spec_file4 = "geoplugin.class.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_dir and 
        all of ($spec_file*)
}