rule PK_BSI_saldo2 : BSI
{
    meta:
        description = "Phishing Kit impersonating Bank Syariah Indonesia (BSI)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-03-30"
        comment = "Phishing Kit - BSI - 'saldo'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "req"
        $spec_dir2 = "auth"
                $spec_file = "otp.html"
        $spec_file2 = "saldo.php"
        $spec_file3 = "mailman.php"
        $spec_file4 = "telegram.php"
        $spec_file5 = "otp.png"
        $spec_file6 = "bank-syariah-indonesia.webflow.681e682db.css"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}