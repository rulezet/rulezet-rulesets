rule PK_GCash_luffy : GCash
{
    meta:
        description = "Phishing Kit impersonating GCash"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-20"
        comment = "Phishing Kit - GCash - 'Developed by ph.luffy 2021'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Gcash_database"
        $spec_dir2 = "Gcash_files"
                $spec_file = "gcash_logs.php"
        $spec_file2 = "mpin-login.php"
        $spec_file3 = "telegram-otp2.php"
        $spec_file4 = "wrong-mpin-login.php"
        $spec_file5 = "_admin.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}