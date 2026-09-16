rule PK_FirstNationalBank_verification : FirstNationalBank
{
    meta:
        description = "Phishing Kit impersonating First National Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-13"
        comment = "Phishing Kit - First National Bank - multiple 'verification' files"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Online Banking_files"
        $spec_dir1 = "ebucks-rewards_files"
                $spec_file = "verification_55.php"
        $spec_file2 = "tick.JPG"
        $spec_file3 = "activityi.html"
        $spec_file4 = "phone-verification.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and 
        all of ($spec_dir*) and 
                all of ($spec_file*)
}