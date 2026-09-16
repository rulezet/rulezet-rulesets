rule PK_Spectrum_Sycho : Spectrum
{
    meta:
        description = "Phishing Kit impersonating Spectrum"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-01-06"
        comment = "Phishing Kit - Spectrum - 'SYCHO'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "Email.php"
        $spec_file2 = "5.html"
        $spec_file3 = "hostname_check.php"
	    $spec_file4 = "main-e0840a2377ffb951560096d54780f0cc.css"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_file4
}