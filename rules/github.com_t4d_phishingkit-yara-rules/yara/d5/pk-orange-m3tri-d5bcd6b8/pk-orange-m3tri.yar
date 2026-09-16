rule PK_Orange_m3tri : Orange
{
    meta:
        description = "Phishing Kit impersonating Orange"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-14"
        comment = "Phishing Kit - Orange - 'M3tri'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "M3tri-hash-bots"
                $spec_file = "defender.php"
        $spec_file2 = "fun1.php"
        $spec_file3 = "fun.php"
	    $spec_file4 = "o_onei_responsive.css"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and 
	    all of ($spec_dir*)
}