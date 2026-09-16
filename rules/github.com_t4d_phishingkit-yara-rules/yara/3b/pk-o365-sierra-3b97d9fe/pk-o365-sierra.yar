rule PK_O365_sierra : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-03-19"
        comment = "Phishing Kit - O365 - 'Sierra Title Password Authorization_files'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "Sierra Title Password Authorization_files"
                $spec_file = "sierratitle.php"
        $spec_file2 = "Pfailed.php"
        $spec_file3 = "default_validatorconstants_en.js"
        $spec_file4 = "securedbyzix.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and 
        all of ($spec_dir*) and 
                all of ($spec_file*)
}