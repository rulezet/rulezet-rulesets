rule PK_RedstoneFCU_forge : RedstoneFCU
{
    meta:
        description = "Phishing Kit impersonating Redstone Federal Credit Union"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-06-17"
        comment = "Phishing Kit - Redstone Federal Credit Union - 'From: xforgex'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "session"
        $spec_dir2 = "a_data"
                $spec_file = "sbretry.php"
        $spec_file2 = "sbcodet.php"
        $spec_file3 = "retry.php"
        $spec_file4 = "Dila_DZ.php"
        $spec_file5 = "05345-logo-sm-xs-publish.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}