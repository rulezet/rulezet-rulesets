rule PK_Dana_ressult: Dana
{
    meta:
        description = "Phishing Kit impersonating Dana.id"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-07-09"
        comment = "Phishing Kit - Dana - 'RESSULT DANA'"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_dir = "devvlopkyy"
        $spec_dir2 = "req"
                $spec_file = "hp01.php"
        $spec_file2 = "masuk.html"
        $spec_file3 = "verifikas1.html"
        $spec_file4 = "bygyrozyee.mp4"
        $spec_file5 = "cove-dana.png"

    condition:
                uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}