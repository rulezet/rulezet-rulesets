rule PK_Absa_oreoo : Absa
{
    meta:
        description = "Phishing Kit impersonating Absa"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-19"
        comment = "Phishing Kit - Absa Online - 'CREATED BY Walid Nabil (OREOO)'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "registration"
                $spec_file = "BOT_12.php"
        $spec_file2 = "App/absa.css"
        $spec_file3 = "YOUR_EMAIL.php"
        $spec_file4 = "send_ConfirmApp.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}