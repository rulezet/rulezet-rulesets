rule PK_PNC_mky : PNC
{
    meta:
        description = "Phishing Kit impersonating PNC online bank"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2022-10-01"
        comment = "Phishing Kit - PNC - 'CREATED BY MkY'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "CrawlerDetect"
        $spec_dir1 = "file"
        $spec_dir2 = "Os"
                $spec_file = "crawlerdetect.php"
        $spec_file2 = "securityq.php"
        $spec_file3 = "c20kdg.php"
        $spec_file4 = "Send.php"
        $spec_file5 = "SpamReferrers.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}