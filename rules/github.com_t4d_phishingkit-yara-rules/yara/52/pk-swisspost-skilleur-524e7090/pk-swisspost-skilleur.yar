rule PK_SwissPost_skilleur : SwissPost
{
    meta:
        description = "Phishing Kit impersonating Swiss Post"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-11-01"
        comment = "Phishing Kit - Swiss Post - by '>SKILLEUR<'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "wait"
                $spec_file = "Done.html"
        $spec_file2 = "smserror.php"
        $spec_file3 = "0035.png"
        $spec_file4 = "lmo.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        $spec_dir
}