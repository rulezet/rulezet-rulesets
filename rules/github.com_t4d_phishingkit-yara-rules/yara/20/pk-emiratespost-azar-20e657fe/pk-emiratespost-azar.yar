rule PK_EmiratesPost_azar : EmiratesPost
{
    meta:
        description = "Phishing Kit impersonating EmiratesPost"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-04-26"
        comment = "Phishing Kit - EmiratesPost - 'Make By ==> Telegram : @Azar_ox'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "anti__boot"
        $spec_dir2 = "all_mixing"
                $spec_file = "cc.php"
        $spec_file2 = "loading_4.php"
        $spec_file3 = "sms_err.php"
        $spec_file4 = "Emarats.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*) 
}