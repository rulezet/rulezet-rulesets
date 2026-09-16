rule PK_AdobePDF_nayfercrax : Adobe
{
    meta:
        description = "Phishing Kit impersonating Adobe PDF Online"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-05"
        comment = "Phishing Kit - Adobe PDF Online - 'Coded by @nayfercrax'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "email"
        $spec_dir1 = "myconfig"
        $spec_dir2 = "api"
                $spec_file = "kill.txt"
        $spec_file2 = "aol.php"
        $spec_file3 = "microsoft.php"
        $spec_file4 = "telegram.php"
        $spec_file5 = "microsoft_logo.svg"
        $spec_file6 = "CTZ_Green-01.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}