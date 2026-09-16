rule PK_UnionBank_cc : UnionBank
{
    meta:
        description = "Phishing Kit impersonating UnionBank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-01"
        comment = "Phishing Kit - UnionBank - 'Team CCs'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "unionbank_files"
                $spec_file = "profile.php"
        $spec_file2 = "first-otp.php"
        $spec_file3 = "m-process.php"
        $spec_file4 = "o1-process.php"
        $spec_file5 = "unionbank.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}