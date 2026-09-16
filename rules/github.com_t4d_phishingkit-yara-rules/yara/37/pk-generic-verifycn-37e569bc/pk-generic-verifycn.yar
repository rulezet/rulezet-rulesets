rule PK_Generic_verifycn : verifyCN_Generic
{
    meta:
        description = "Phishing Kit - Z10n - Generic email credentials stealer"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-09"
        comment = "Phishing Kit - 'From: VerifyCN'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "support"
                $spec_file = "access1.php"
        $spec_file1 = "access2.php"
        $spec_file2 = "auth.php"
        $spec_file3 = "go.php"
        $spec_file4 = "modal.jpg"
        $spec_file5 = "signin.jpg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}