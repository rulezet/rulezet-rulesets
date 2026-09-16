rule PK_Generic_Z10n : Z10n_Generic
{
    meta:
        description = "Phishing Kit - Z10n - Generic email credentials stealer"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-05-23"
        comment = "Phishing Kit - '- by Z10n -'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Admin"
                $spec_file = "acct.php"
        $spec_file2 = "adm.html"
        $spec_file3 = "Finish.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}