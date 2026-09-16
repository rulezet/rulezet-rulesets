rule PK_Liberbank_metri : Liberbank
{
    meta:
        description = "Phishing Kit impersonating Liberbank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-18"
        comment = "Phishing Kit - Liberbank - '$METRI_TOKEN'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "M3tri-hash-bots"
        $spec_dir2 = "LB-files"
                $spec_file = "LB-infos.php"
        $spec_file2 = "LB-rd-otp.php"
        $spec_file3 = "liberbank-rzlt.txt"
        $spec_file4 = "visited-ips.txt"
        $spec_file5 = "anti9.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}