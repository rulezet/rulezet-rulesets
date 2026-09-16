rule PK_MTBank_rd569 : MT_Bank
{
    meta:
        description = "Phishing Kit impersonating M&T Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-12-08"
        comment = "Phishing Kit - M&T Bank - dir named 'm&t-bank-RD569-detail2'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "css"
        $spec_dir1 = "images"
                $spec_file1 = "em.html"
        $spec_file2 = "next.php"
        $spec_file3 = "email.php"
        $spec_file4 = "css.css"
        $spec_file5 = "mtb-equalhousinglender.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*) 
}