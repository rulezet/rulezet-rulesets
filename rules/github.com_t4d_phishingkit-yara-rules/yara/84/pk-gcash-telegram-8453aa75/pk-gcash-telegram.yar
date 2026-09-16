rule PK_GCash_telegram : GCash
{
    meta:
        description = "Phishing Kit impersonating GCash"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-08-31"
        comment = "Phishing Kit - GCash - using Telegram for exfiltration"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "gcash_js"
        $spec_dir2 = "Gcash_files"
                $spec_file = "tele_bot.php"
        $spec_file2 = "config.php"
        $spec_file3 = "mpin-redir-login.php"
        $spec_file4 = "otp-login.php"
        $spec_file5 = "mpinerror2.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}