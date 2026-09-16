rule PK_Chase_mody : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-10-11"
        comment = "Phishing Kit - Chase Bank - 'From: Mody@BOA'"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_dir = "Mody"
                $spec_file = "mody.php"
        $spec_file1 = "otp.php"
        $spec_file2 = "to2.php"
        $spec_file3 = "email3.php"
        $spec_file4 = "verifymail3.css"

    condition:
                uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}