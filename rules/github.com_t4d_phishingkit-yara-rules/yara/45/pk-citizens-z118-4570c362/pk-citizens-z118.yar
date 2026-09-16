rule PK_Citizens_z118 : CitizensBank
{
    meta:
        description = "Phishing Kit impersonating Citizens Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-09"
        comment = "Phishing Kit - CitizensBank - '$Z118_EMAIL'"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_dir = "functions"
        $spec_dir2 = "logs"
                $spec_file1 = "citizensns.min.2574.css"
        $spec_file2 = "billing.php"
        $spec_file3 = "config.php"
        $spec_file4 = "CTZ_Green-01.png"
        $spec_file5 = "fullz.php"

    condition:
                uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}