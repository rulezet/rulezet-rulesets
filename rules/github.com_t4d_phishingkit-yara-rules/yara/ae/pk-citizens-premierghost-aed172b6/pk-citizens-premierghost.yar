rule PK_Citizens_premierghost : CitizensBank
{
    meta:
        description = "Phishing Kit impersonating Citizens Bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.linkedin.com/posts/stalkphish_scama-pr0n-activity-7198548331063640064-oWAy?utm_source=share&utm_medium=member_desktop"
        date = "2024-05-27"
        comment = "Phishing Kit - CitizensBank - 'PremierGhost & Elysium'"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_dir = "Exo"
        $spec_dir2 = "Guard"
                $spec_file1 = "ChangeMe.ini"
        $spec_file2 = "complete.php"
        $spec_file3 = "verify.php"
        $spec_file4 = "Att.php"
        $spec_file5 = "CTZ_Green-01.png"

    condition:
                uint32(0) == 0x04034b50 and 
	    $local_file and 
	    all of ($spec_dir*) and 
	    all of ($spec_file*)
}