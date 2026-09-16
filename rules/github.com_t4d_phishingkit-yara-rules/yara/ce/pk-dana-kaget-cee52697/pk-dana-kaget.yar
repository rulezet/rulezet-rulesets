rule PK_Dana_kaget: Dana
{
    meta:
        description = "Phishing Kit impersonating Dana.id"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-08-18"
        comment = "Phishing Kit - Dana - '= Info Login DANA KAGET ='"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_dir = "dana_pin"
        $spec_dir2 = "dana_otp1"
                $spec_file = "int.html"
        $spec_file2 = "telegram.php"
        $spec_file3 = "kaget.css"
        $spec_file4 = "dana_logo.png"

    condition:
                uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}