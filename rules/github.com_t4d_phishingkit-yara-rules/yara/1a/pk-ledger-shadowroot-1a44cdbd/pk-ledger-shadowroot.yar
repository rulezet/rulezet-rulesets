rule PK_Ledger_shadowroot : Ledger
{
    meta:
        description = "Phishing Kit impersonating Ledger"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.linkedin.com/posts/stalkphish_phishingkit-phishing-activity-7267436169104183296-vXzv/"
        date = "2024-11-27"
        comment = "Phishing Kit - Ledger - backdoored phishingkit"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "img"
                $spec_file = "typeahead.min.js"
        $spec_file2 = "login.php"
        $spec_file3 = "tools.html"
        $spec_file4 = "script3.js"
        $spec_file5 = "nano_s_plus.png"
        $spec_file6 = "recovery.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}