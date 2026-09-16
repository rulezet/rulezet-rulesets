rule PK_MTB_nayfer : MT_Bank
{
    meta:
        description = "Phishing Kit impersonating M&T Bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-11-10"
        comment = "Phishing Kit - M&T Bank - 'nayfer'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "server"
        $spec_dir2 = "dist"
        $spec_file = "account_verify.php"
        $spec_file2 = "mtb-equalhousinglender.svg"
        $spec_file3 = "telegram.php"
        $spec_file4 = "lo.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_dir*) and 
        all of ($spec_file*)
}