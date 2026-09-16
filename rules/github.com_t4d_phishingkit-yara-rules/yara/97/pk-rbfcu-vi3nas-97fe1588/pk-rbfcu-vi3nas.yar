rule PK_RBFCU_vi3nas : RBFCU
{
    meta:
        description = "Phishing Kit impersonating Randolph-Brooks Federal Credit Union"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2021-01-21"
        comment = "Phishing Kit - RBFCU - 'Created By vi3nas'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "log.htm"
        $spec_file2 = "next.htm"
        $spec_file3 = "Rezults.txt"
        $spec_file4 = "verify2.php"
        $spec_file5 = "verify.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*)
}