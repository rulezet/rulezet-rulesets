rule PK_AdobePDF_venza2 : Adobe
{
    meta:
        description = "Phishing Kit impersonating Adobe PDF Online"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-13"
        comment = "Phishing Kit - Adobe PDF Online - 'cReAtEd By VeNzA'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
        $spec_dir1 = "images"
                $spec_file = "next.php"
        $spec_file2 = "index.php"
        $spec_file3 = "office3651.png"
        $spec_file4 = "sharepoint-portals.svg"
        $spec_file5 = "demo-page.css"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}