rule PK_Boursorama_xoxo : Boursorama
{
    meta:
        description = "Phishing Kit impersonating Boursorama"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-16"
        comment = "Phishing kit - Boursorama - 'boursorama log By XoXo'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "connexion"
        $spec_dir1 = "bundles"
                $spec_file = "boursorama-banque-logo@2x.png"
        $spec_file2 = "snd4.php"
        $spec_file3 = "otp2.php"
        $spec_file4 = "fin.php"
        $spec_file5 = "DSP2_actu_Covid19.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}