rule PK_Ledger_webwallet : Ledger
{
    meta:
        description = "Phishing Kit impersonating Ledger"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-12-15"
        comment = "Phishing Kit - Ledger - using 'webwallet_files' filename directory"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "webwallet_files"
        $spec_dir2 = "warning"
        $spec_dir3 = "config"
                $spec_file = "process.php"
        $spec_file2 = "cxbtop.txt"
        $spec_file3 = "telegram.php"
        $spec_file4 = "send.PNG"
        $spec_file5 = "ledger-logo.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}