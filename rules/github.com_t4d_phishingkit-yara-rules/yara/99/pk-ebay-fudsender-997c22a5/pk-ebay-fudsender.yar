rule PK_Ebay_fudsender : EBay
{
    meta:
        description = "Phishing Kit impersonating Ebay"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-28"
        comment = "Phishing Kit - EBay - 'fudsender(dot)com'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
                $spec_file = "34wtddjp0q1v1dtu2elv5jwg4yf.css"
        $spec_file2 = "signin-render-ZiemCn4H.css"
        $spec_file3 = "next.php"
        $spec_file4 = "email.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                all of ($spec_file*)
}