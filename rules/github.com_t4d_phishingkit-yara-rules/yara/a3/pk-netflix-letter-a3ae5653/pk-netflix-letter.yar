rule PK_Netflix_letter : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-16"
        comment = "Phishing Kit - Netflix - with a HTML letter draft"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "actions"
        $spec_dir1 = "steps"
        $spec_dir2 = "prevents"
                $spec_file = "Letter.html"
        $spec_file2 = "error_on_login.php"
        $spec_file3 = "loading_apple_pay.php"
        $spec_file4 = "timer_finished.js"
        $spec_file5 = "cloudflare.jpg"
        $spec_file6 = "key.inc.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}