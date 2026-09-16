rule PK_Sparkasse_nn : Sparkasse
{
    meta:
        description = "Phishing Kit impersonating Sparkasse"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-05-17"
        comment = "Phishing Kit - Sparkasse - 'From: nn'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Sparkasse_files"
                $spec_file = "firedown.php"
        $spec_file2 = "index.htm"
        $spec_file3 = "sparkasse.css"
        $spec_file4 = "harsh2-0.png"


    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}