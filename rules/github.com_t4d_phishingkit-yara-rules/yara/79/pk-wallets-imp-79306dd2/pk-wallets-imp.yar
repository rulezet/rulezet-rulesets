rule PK_Wallets_imp : GenericWallets
{
    meta:
        description = "Phishing Kit impersonating several wallet providers"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-21"
        comment = "Phishing Kit - GenericWallets - found in a imp.zip file"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "WalletAPI_wallets_files"
        $spec_dir2 = "tokens"
                $spec_file = "authenticate.html"
        $spec_file2 = "main2.css"
        $spec_file3 = "SFMono-Boldd41dd41dd41d.html"
        $spec_file4 = "flourishing.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}