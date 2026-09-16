rule PK_WellsFargo_dbcopper : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-22"
        comment = "Phishing Kit - Wells Fargo - '- @dbc0pp3r W3LL$ F4RG0 -'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "imgs"
        $spec_dir2 = "killer_k"
                $spec_file = "con.ini"
        $spec_file2 = "c.php"
        $spec_file3 = "persent1.php"
        $spec_file4 = "wells-fargo-volunteer-gardening_414x240.jpg"
        $spec_file5 = "wellsfargosans-rg.woff2"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}