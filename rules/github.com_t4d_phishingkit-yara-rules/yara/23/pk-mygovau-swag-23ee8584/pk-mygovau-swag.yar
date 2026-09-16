rule PK_MyGovAU_swag : MyGovAU
{
    meta:
        description = "Phishing Kit impersonating MyGov Australian Government"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-27"
        comment = "Phishing kit - MyGovAU - 'SWAG myGOVau RzLt'"        

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "content"
                $spec_file = "dswag.php"
        $spec_file2 = "dswag2.php"
        $spec_file3 = "index2.html"
        $spec_file4 = "blugov.css"
        $spec_file5 = "myGov-logo-cobranded-black.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}