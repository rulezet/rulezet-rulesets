rule PK_BankOfAmerica_xsmayer : BankOfAmerica
{
    meta:
        description = "Phishing Kit impersonating Bank Of America"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-05-21"
        comment = "Phishing Kit - BankOfAmerica - 'From: xSmayer<customer@xblack.com>'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
                $spec_file = "result.php"
        $spec_file2 = "action.php"
        $spec_file3 = "action2.php"
        $spec_file4 = "369852.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}