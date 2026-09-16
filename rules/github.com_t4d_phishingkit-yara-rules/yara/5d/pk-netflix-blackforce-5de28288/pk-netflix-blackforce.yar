rule PK_Netflix_blackforce : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-22"
        comment = "Phishing Kit - Netflix - 'Coded By Root_Dr'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "botActBan"
        $spec_dir1 = "config"
        $spec_dir2 = "prevents"
                $spec_file = "visitors.html"
        $spec_file2 = "banIpAct.php"
        $spec_file3 = "crawler-user-agents.json"
        $spec_file4 = "captcha.php"
        $spec_file5 = "ngif.gif"
        $spec_file6 = "insert.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}