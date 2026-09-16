rule PK_Nedbank_xxxcashout2 : Nedbank
{
    meta:
        description = "Phishing Kit impersonating Nedbank"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2024-01-23"
        comment = "Phishing Kit - Nedbank - 'XXXCASHOUT' - version 2"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "zzz"
        $spec_dir2 = "app"
                $spec_file = "post3.php"
        $spec_file2 = "app-confirmation.php"
        $spec_file3 = "otp-verification.php"
        $spec_file4 = "Email.php"
        $spec_file5 = "Eye-Hide.105fff437c32e67f.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}