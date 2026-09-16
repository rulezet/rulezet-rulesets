rule PK_MTBank_venza : MT_Bank
{
    meta:
        description = "Phishing Kit impersonating M&T Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-27"
        comment = "Phishing Kit - M&T Bank - '- CrEaTeD bY VeNzA -'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "smoth"
        $spec_dir1 = "includes"
                $spec_file = "em.html"
        $spec_file2 = "user_details.php"
        $spec_file3 = "config.php"
        $spec_file4 = "detail.html"
        $spec_file5 = "mtb-logo.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*) 
}