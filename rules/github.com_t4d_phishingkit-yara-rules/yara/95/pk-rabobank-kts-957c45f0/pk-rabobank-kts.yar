rule PK_Rabobank_kts : Rabobank
{
    meta:
        description = "Phishing Kit impersonating Rabobank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-18"
        comment = "Phishing Kit - Rabobank - 'Page made by KTS team'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "a1b2c3"
        $spec_dir2 = "token"
        $spec_dir3 = "ng"

                $spec_file = "Mobile_Detect.php"
        $spec_file2 = "cloaker.php"
        $spec_file3 = "rabobank_logo.png"
        $spec_file4 = "file.php"
        $spec_file5 = "class.jabber.php"
        $spec_file6 = "jabber.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}