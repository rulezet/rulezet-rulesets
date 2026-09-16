rule PK_BankOfAmerica_history : BankOfAmerica
{
    meta:
        description = "Phishing Kit impersonating Bank Of America"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-24"
        comment = "Phishing Kit - BankOfAmerica - using several history* HTML files"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "css"
        $spec_dir2 = "images"
        $spec_file = "history1.html"
        $spec_file2 = "redirect2.html"
        $spec_file3 = "balance.css"
        $spec_file4 = "tog2.PNG"
        $spec_file5 = "boa log2.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}