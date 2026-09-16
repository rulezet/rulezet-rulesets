rule PK_NavyFederal_panda : NavyFederal
{
    meta:
        description = "Phishing Kit impersonating Navy Federal Credit Union"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-10"
        comment = "Phishing Kit - Navy Federal - '<[ Thanks to PANDA ]>'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "manger"
        $spec_dir2 = "account"
                $spec_file = "captcha.php"
        $spec_file2 = "myaccount.php"
        $spec_file3 = "step3.php"
        $spec_file4 = "confirmation.php"
        $spec_file5 = "nfcu-icons.ttf"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}