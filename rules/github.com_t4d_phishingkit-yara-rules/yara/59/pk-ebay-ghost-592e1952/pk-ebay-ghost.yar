rule PK_Ebay_Ghost : EBay
{
    meta:
        description = "Phishing Kit impersonating Ebay"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-04"
        comment = "Phishing Kit - EBay - '---|Ghost Rider|---'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
                $spec_file = "34wtddjp0q1v1dtu2elv5jwg4yf.css"
        $spec_file2 = "geoplugin.class.php"
        $spec_file3 = "data.php"
        $spec_file4 = "Login.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                $spec_file and
        $spec_file2 and
        $spec_file3 and
	    $spec_file4
}