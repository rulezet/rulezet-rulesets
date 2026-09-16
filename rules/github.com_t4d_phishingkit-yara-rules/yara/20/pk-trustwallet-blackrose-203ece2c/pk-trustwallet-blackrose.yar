rule PK_TrustWallet_blackrose : TrustWallet
{
    meta:
        description = "Phishing Kit impersonating Trust Wallet"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-02-09"
        comment = "Phishing Kit - Trust Wallet - 'Main Author: @BLACKROSE_1337'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Folder"
        $spec_dir2 = "TS"
        $spec_dir3 = "system"
                $spec_file = "Info_Processing.php"
        $spec_file2 = "logo(35).png"
        $spec_file3 = "login_wallet24.js"
        $spec_file4 = "Opane.html"


    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}