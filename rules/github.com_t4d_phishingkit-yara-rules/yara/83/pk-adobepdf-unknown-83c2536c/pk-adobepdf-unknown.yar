rule PK_AdobePDF_unknown : Adobe
{
    meta:
        description = "Phishing Kit impersonating Adobe PDF online"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-31"
        comment = "Phishing Kit - Adobe PDF Online - 'Created BY unknown'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "autoregpdf"
                $spec_file = "Use Method.txt"
        $spec_file2 = "iz.php"
        $spec_file3 = "index.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                $spec_file and
        $spec_file2 and
        $spec_file3
}