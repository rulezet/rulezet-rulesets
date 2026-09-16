rule PK_AdobePDF_dotloop : Adobe
{
    meta:
        description = "Phishing Kit impersonating Adobe PDF Online"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-28"
        comment = "Phishing Kit - Adobe PDF Online - 'From: Dotloop'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "asset" 
                $spec_file = "signin.php"
        $spec_file2 = "contract.jpg"
        $spec_file3 = "Microsoft_Edge_logo_(2019).svg.png"
        $spec_file4 = "KYC-ENG (confidential).pdf"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}