rule PK_Mweb_jeff : Mweb
{
    meta:
        description = "Phishing Kit impersonating Mweb"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-09"
        comment = "Phishing Kit - Mweb - jeff.php"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "mweb"
                $spec_file = "jeff.php"
        $spec_file2 = "Screenshot_2.png"
        $spec_file3 = "style.css"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_dir
}