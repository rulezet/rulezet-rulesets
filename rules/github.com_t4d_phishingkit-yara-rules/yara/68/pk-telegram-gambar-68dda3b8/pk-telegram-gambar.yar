rule PK_Telegram_gambar : Telegram
{
    meta:
        description = "Phishing Kit impersonating Telegram (Malaysian users)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-11-29"
        comment = "Phishing Kit - Telegram - targeting Malaysian victims"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "ast"
        $spec_dir2 = "xLtRfgv"
        $spec_dir3 = "img-apple-160"
                $spec_file = "2af.js"
        $spec_file2 = "otp.js"
        $spec_file3 = "otp.php"
        $spec_file4 = "1f1f2-1f1fe.png"
        $spec_file5 = "Gambar WhatsApp 2024-09-10 pukul 23.48.57_1a5aa7b6.jpg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}