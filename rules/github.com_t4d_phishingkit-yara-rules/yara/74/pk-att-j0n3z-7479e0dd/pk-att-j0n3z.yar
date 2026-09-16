rule PK_ATT_j0n3z : ATandT
{
    meta:
        description = "Phishing Kit impersonating ATandT"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-09"
        comment = "Phishing Kit - ATandT - 'Created By j0n3z'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "proxyblock.php"
        $spec_file2 = "vti.php"
        $spec_file3 = "lg.html"
        $spec_file4 = "nyb2.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3 and 
        $spec_file4
}