rule PK_FirstAmerican_jasper : FirstAmerican
{
    meta:
        description = "Phishing Kit impersonating First American insurance"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-05-12"
        comment = "Phishing Kit - First American - '[FA] JaSpEr $ip'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "0.php"
        $spec_file2 = "Borrower's-details.php"
        $spec_file3 = "Borrower's-details.shtml"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*)
}