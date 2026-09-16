rule PK_Commerzbank_gus : Commerzbank
{
    meta:
        description = "Phishing Kit impersonating Commerzbank AG"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-04"
        comment = "Phishing Kit - Commerzbank - 'Coded By Gus'"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_dir = "default"
        $spec_dir2 = "send"
                $spec_file = "settings.php"
        $spec_file1 = "3.php"
        $spec_file2 = "account_sessionAuth.php"
        $spec_file3 = "nachprufung.php"
        $spec_file4 = "neu_png.png"
        $spec_file5 = "main4ac6.js"

    condition:
                uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}