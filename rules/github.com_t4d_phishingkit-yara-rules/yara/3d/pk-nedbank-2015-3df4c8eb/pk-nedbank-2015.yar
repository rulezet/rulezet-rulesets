rule PK_Nedbank_2015 : Nedbank
{
    meta:
        description = "Phishing Kit impersonating Nedbank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-21"
        comment = "Phishing Kit - Nedbank - 'NED 2015 Access dETAILS'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "processing.html"
        $spec_file2 = "continue2.php"
        $spec_file3 = "nedlogon.html"
        $spec_file4 = "Reference.html"
        $spec_file5 = "loadRefrence.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*)
}