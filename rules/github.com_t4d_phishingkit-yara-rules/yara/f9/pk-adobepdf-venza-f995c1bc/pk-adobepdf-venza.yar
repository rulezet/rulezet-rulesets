rule PK_AdobePDF_venza : Adobe
{
    meta:
        description = "Phishing Kit impersonating Adobe PDF Online"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-05-16"
        comment = "Phishing Kit - Adobe PDF Online - 'cReAtEd By VeNzA'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Adobe1"
                $spec_file = "tom.php"
        $spec_file2 = "kancha.php"
        $spec_file3 = "index-2.html"
        $spec_file4 = "fade.gif"
        $spec_file5 = "sina.gif"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}