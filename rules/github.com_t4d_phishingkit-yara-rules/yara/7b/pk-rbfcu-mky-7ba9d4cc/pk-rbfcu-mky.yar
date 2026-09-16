rule PK_RBFCU_mky : RBFCU
{
    meta:
        description = "Phishing Kit impersonating Randolph-Brooks Federal Credit Union"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2022-11-09"
        comment = "Phishing Kit - RBFCU - 'CREATED BY @MKYDAGOAT'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "botfucker"
        $spec_dir1 = "Os"
                $spec_file = "securityq.php"
        $spec_file2 = "ncua.png"
        $spec_file3 = "crawlerdetect.php"
        $spec_file4 = "useragent.dat"
        $spec_file5 = "SpamReferrers.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}