rule PK_Citizens_freddy : CitizensBank
{
    meta:
        description = "Phishing Kit impersonating Citizens Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://twitter.com/Stalkphish_io/status/1550023405738622976"
        date = "2022-07-21"
        comment = "Phishing Kit - CitizensBank - 'FREDDY'S GANG Citizen Bank Info'"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_dir = "darkx"
        $spec_dir2 = "access"
                $spec_file1 = "mainnet.php"
        $spec_file2 = "recon.php"
        $spec_file3 = "question_auth.php"
        $spec_file4 = "credit_verify.html"

    condition:
                uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}