rule PK_Ledger_live : Ledger
{
    meta:
        description = "Phishing Kit impersonating Ledger"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-06-02"
        comment = "Phishing Kit - Ledger - using 'Ledger Live' title"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "clear"
        $spec_dir2 = "includes"
        $spec_dir3 = "config"
                $spec_file = "wallet_recovery.html"
        $spec_file2 = "connect.php"
        $spec_file3 = "config.txt"
        $spec_file4 = "bip39.min.js"
        $spec_file5 = "Ledger-recover-homepage.webp"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}