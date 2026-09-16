rule PK_Generic_RD337 : RD337_Generic
{
    meta:
        description = "Phishing Kit - RD337 - Generic email credentials stealer"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2022-01-29"
        comment = "Phishing Kit - RD337"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "images"
                $spec_file = "26-269507_arbys-logo-transparent-norton-secured-logo-png-png.png"
        $spec_file2 = "next.php"
        $spec_file3 = "email.php"
        $spec_file4 = "favicons"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}