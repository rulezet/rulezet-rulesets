rule PK_Excel_511 : Excel
{
    meta:
        description = "Phishing Kit impersonating Excel page"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-12"
        comment = "Phishing Kit - Excel - contain 511.php file"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "ajax.googleapis.com"
        $spec_dir2 = "js"
                $spec_file = "511.php"
        $spec_file2 = "tether.js"
        $spec_file3 = "scripts.js"
        $spec_file4 = "spinner.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}