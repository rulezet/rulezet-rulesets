rule PK_BankOfAmerica_yochi : BankOfAmerica
{
    meta:
        description = "Phishing Kit impersonating Bank Of America"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-09"
        comment = "Phishing Kit - BankOfAmerica - 'YOCHI SCAMA CONFIGURATION FILE'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "autob"
        $spec_dir2 = "bstyles"
                $spec_file = "infile.php"
        $spec_file2 = "hh.php"
        $spec_file3 = "basicbot.php"
        $spec_file4 = "BofA_rgb.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}