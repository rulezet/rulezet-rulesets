rule PK_Facebook_oreooo : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-10-04"
        comment = "Phishing Kit - Facebook - 'THIS SCAM WAS CREATED BY #OREOO'"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_dir = "home"
                $spec_file = "send_login.php"
        $spec_file2 = "system.php"
        $spec_file3 = "BOT_6.php"
        $spec_file4 = "DJTV3bRb1M3.js.download"
        $spec_file5 = "2.png"

    condition:
                uint32(0) == 0x04034b50 and 
	   $local_file and 
	   $spec_dir and 
	   all of ($spec_file*)
}