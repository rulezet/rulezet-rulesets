rule PK_Orange_fun : Orange
{
    meta:
        description = "Phishing Kit impersonating Orange"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-24"
        comment = "Phishing Kit - Orange - 'fun.php' page"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "password.php"
        $spec_file2 = "finish.php"
        $spec_file3 = "fun.php"
	    $spec_file4 = "logo-orange.png"
        $spec_file5 = "fin.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*)
}