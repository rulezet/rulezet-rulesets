rule PK_Ledger_alpha : Ledger
{
    meta:
        description = "Phishing Kit impersonating Ledger"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-02"
        comment = "Phishing Kit - Ledger - 'From: bper <no@alpha.com>'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Ledger Support_files"
                $spec_file = "check3.php"
        $spec_file2 = "LedgerSupport.html"
        $spec_file3 = "768d0df29086c98763c6c0907a5aed1f76ae9306.svg"
        $spec_file4 = "bip39.browser.min.js.download"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}