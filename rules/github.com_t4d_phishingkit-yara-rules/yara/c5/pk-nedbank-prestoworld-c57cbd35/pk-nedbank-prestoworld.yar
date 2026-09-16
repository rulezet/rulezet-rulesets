rule PK_Nedbank_prestoworld : Nedbank
{
    meta:
        description = "Phishing Kit impersonating Nedbank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-12-21"
        comment = "Phishing Kit - Nedbank - 'AUTHOR : PRESTOWORLD'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "app"
        $spec_dir2 = "bots"
        $spec_dir3 = "panel"
                $spec_file = "md.php"
        $spec_file2 = "user2.php"
        $spec_file3 = "animation-checkmark.gif"
        $spec_file4 = "ajax-loader.b1d2d7c201430a631bcd.gif"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}