rule PK_ATT_jeff : ATandT
{
    meta:
        description = "Phishing Kit impersonating ATandT"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-16"
        comment = "Phishing Kit - ATandT - using jeff_.php files"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "jeff3.php"
        $spec_file2 = "jeff2.php"
        $spec_file3 = "jeff.php"
        $spec_file4 = "index4.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3 and 
        $spec_file4
}