rule PK_MyGovAU_yochi : MyGovAU
{
    meta:
        description = "Phishing Kit impersonating MyGov Australian Government"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-02"
        comment = "Phishing kit - MyGovAU - 'SCAM PAGE MY GOV #By YOCHI'"        

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "autob"
        $spec_dir1 = "home"
                $spec_file = "btm.php"
        $spec_file2 = "nth.php"
        $spec_file3 = "process.php"
        $spec_file4 = "myGov-cobranded-logo-black.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}