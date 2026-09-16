rule PK_WooCommerce_tg : WooCommerce
{
    meta:
        description = "Phishing Kit impersonating WooCommerce.com"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-04-03"
        comment = "Phishing Kit - WooCommerce - using telegram for exfiltration"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
        $spec_dir2 = "images"
                $spec_file = "telegram.php"
        $spec_file1 = "record.txt"
        $spec_file2 = "next.php"
        $spec_file4 = "woo.png"
        $spec_file5 = "8316.0ce0ab45487acf8d1ff1.min.css"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_dir*) and 
        all of ($spec_file*)
}