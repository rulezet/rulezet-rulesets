rule PK_NAB_otp : NAB
{
    meta:
        description = "Phishing Kit impersonating National Australia Bank (NAB)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-22"
        comment = "Phishing kit - NAB - retrieve OTP"        

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "post"
                $spec_file = "otp1.php"
        $spec_file2 = "antiip.php"
        $spec_file3 = "resms.php"
        $spec_file4 = "timer.php"
        $spec_file5 = "loading-25.gif"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}