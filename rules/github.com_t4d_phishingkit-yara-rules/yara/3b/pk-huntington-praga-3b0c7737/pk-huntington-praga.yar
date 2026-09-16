rule PK_Huntington_praga : Huntington
{
    meta:
        description = "Phishing Kit impersonating Huntington bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-09-30"
        comment = "Phishing Kit - Huntington Bank - '&id=$praga$praga'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "hunt"
                $spec_file = "email.php"
        $spec_file2 = "need4.php"
        $spec_file3 = "surf5.php"
    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                $spec_file and
        $spec_file2 and
        $spec_file3
}