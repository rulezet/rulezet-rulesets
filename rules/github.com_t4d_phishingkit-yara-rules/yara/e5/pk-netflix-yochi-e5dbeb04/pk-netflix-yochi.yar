rule PK_Netflix_yochi : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-07"
        comment = "Phishing Kit - Netflix - 'SCAM PAGE NETFLIX #By YOCHI, WORK HARD DREAM B!G'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "admin"
        $spec_dir2 = "fad58"
                $spec_file = "proc.php"
        $spec_file2 = "infile.php"
        $spec_file3 = "upp.php"
        $spec_file4 = "nf-icon-v1-93.ttf"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}