rule PK_SouthAfricanPostOffice_7even : SouthAfricanPostOffice
{
    meta:
        description = "Phishing Kit impersonating South African Post Office"
        licence = "GPL-3.0"
        author = "Thomas 'Damonneville"
        reference = ""
        date = "2023-09-26"
        comment = "Phishing Kit - SouthAfricanPostOffice - '7even' banner"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "lib"
        $spec_dir2 = "secure"
                $spec_file = "logininfo.php"
        $spec_file2 = "error2.php"
        $spec_file3 = "simple_html_dom.php"
        $spec_file4 = "pay.php"
        $spec_file5 = "Telegram.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}