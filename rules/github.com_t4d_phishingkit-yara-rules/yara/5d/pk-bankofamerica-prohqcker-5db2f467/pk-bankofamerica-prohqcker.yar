rule PK_BankOfAmerica_prohqcker : BankOfAmerica
{
    meta:
        description = "Phishing Kit impersonating Bank Of America"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-08"
        comment = "Phishing Kit - BankOfAmerica - 'Telegram ID: @prohqcker**BofA'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "bots"
        $spec_dir2 = "images"
                $spec_file = "prohqcker4.php"
        $spec_file2 = "me.php"
        $spec_file3 = "mask.js"
        $spec_file4 = "assets-images-global-logos-BofA_rgb-CSX5624a146.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}