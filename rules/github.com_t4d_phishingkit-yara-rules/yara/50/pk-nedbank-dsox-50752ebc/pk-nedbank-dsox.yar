rule PK_Nedbank_dsox : Nedbank
{
    meta:
        description = "Phishing Kit impersonating Nedbank"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-07-17"
        comment = "Phishing Kit - Nedbank - 'Coded By Dsox DZ'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "enforcer"
        $spec_dir2 = "spox"
                $spec_file = "post2.php"
        $spec_file2 = "blocked.txt"
        $spec_file3 = "rbots.php"
        $spec_file4 = "NedbankExperience.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and 
        all of ($spec_dir*)
}