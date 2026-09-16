rule PK_Galicia_officenest : Galicia
{
    meta:
        description = "Phishing Kit impersonating Galicia online banking"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-05-10"
        comment = "Phishing Kit - Galicia - officenestBot, name of the Telegram bot used"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "images"
        $spec_dir2 = "fonts"
                $spec_file = "configGA.php"
        $spec_file2 = "login4.php"
        $spec_file3 = "asdasffbgfbgdrhryjutipikhjghjhtdgrfgddfgdgfngbgfghtyjuouiytrtfsddddddddddddddkdbhflhsbfkwbroewniflkf.html"
        $spec_file4 = "config.php"
        $spec_file5 = "wink2.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}