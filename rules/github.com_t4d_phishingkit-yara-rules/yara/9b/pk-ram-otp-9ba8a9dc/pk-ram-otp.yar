rule PK_RAM_otp : RAM
{
    meta:
        description = "Phishing Kit impersonating RAM.co.za"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-03-27"
        comment = "Phishing Kit - RAM - retrieved also One-Time-Password code"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "me.php"
        $spec_file2 = "cc.html"
        $spec_file3 = "config.php"
        $spec_file4 = "wait.html"
        $spec_file5 = "coderror.html"
        $spec_file6 = "succes.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*)
}