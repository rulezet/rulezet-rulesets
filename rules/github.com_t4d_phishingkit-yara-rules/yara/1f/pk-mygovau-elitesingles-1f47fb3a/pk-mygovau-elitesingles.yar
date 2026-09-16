rule PK_MyGovAU_elitesingles : MyGovAU
{
    meta:
        description = "Phishing Kit impersonating MyGov Australian Government"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-13"
        comment = "Phishing kit - MyGovAU - 'EliteSingles'"        

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
        $spec_dir1 = "file"
        $spec_dir2 = "images"
                $spec_file = "detail.html"
        $spec_file2 = "thank.html"
        $spec_file3 = "d0c730269ecac3176c758ba99930a36fMy-Pension-Manager.xlsx"
        $spec_file4 = "mgv2-application.css"
        $spec_file5 = "myGov-cobranded-logo-black.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}