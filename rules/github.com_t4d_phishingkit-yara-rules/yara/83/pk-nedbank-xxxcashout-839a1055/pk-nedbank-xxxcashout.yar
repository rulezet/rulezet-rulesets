rule PK_Nedbank_xxxcashout : Nedbank
{
    meta:
        description = "Phishing Kit impersonating Nedbank"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-03-03"
        comment = "Phishing Kit - Nedbank - 'XXXCASHOUT'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "zzz"
        $spec_dir2 = "app"
                $spec_file = "post3.php"
        $spec_file2 = "r4.php"
        $spec_file3 = "zz10.php"
        $spec_file4 = "Email.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}