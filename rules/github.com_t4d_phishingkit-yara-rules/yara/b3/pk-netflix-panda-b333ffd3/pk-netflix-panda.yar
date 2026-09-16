rule PK_Netflix_Panda : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-05-02"
        comment = "Phishing Kit - Netflix - 'Panda'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "prevents"
                $spec_file = "log.txt"
        $spec_file2 = "results.html"
        $spec_file3 = "mine.php"
        $spec_file4 = "HOW_TO_EDIT_SCAMA.txt"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                 all of ($spec_file*)
}