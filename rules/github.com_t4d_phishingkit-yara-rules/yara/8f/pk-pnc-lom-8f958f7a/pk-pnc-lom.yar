rule PK_PNC_lom : PNC
{
    meta:
        description = "Phishing Kit impersonating PNC online bank"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2024-05-13"
        comment = "Phishing Kit - PNC - 'lom@pnc.c0m'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "pnc"
                $spec_file = "finish.php"
        $spec_file2 = "index.html"
        $spec_file3 = "index.php"
        $spec_file4 = "securityupdate.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}