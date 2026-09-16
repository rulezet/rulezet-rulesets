rule PK_MTBank_yochi : MT_Bank
{
    meta:
        description = "Phishing Kit impersonating M&T Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-04-25"
        comment = "Phishing Kit - M&T Bank - 'SCAM PAGE M&T BANK #By YOCHI'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "render"
        $spec_dir1 = "admin"
                $spec_file = "btm.php"
        $spec_file2 = "eav.php"
        $spec_file3 = "suspch.php"
        $spec_file4 = "mtb-logo.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*) 
}