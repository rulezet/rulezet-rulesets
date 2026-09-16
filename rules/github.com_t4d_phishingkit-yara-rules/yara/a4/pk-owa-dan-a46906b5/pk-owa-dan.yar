rule PK_OWA_dan : OWA
{
    meta:
        description = "Phishing Kit impersonating OWA"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-01-01"
        comment = "Phishing Kit - OWA - 'by dan'"

    strings:
                $zip_file = { 50 4b 03 04 }
                                $spec_file = "auth.php"
        $spec_file2 = "index.htm"
        $spec_file3 = "lgntopr.gif"
	$spec_file4 = "owafont.css"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_file4
}