rule PK_UKGov_DVLA : UKGov
{
    meta:
        description = "Phishing Kit impersonating UK Government Gateway"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-03-25"
        comment = "Phishing Kit - UK Gov. - Tax payment"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "fonts"
                $spec_file = "doc_5.html"
        $spec_file2 = "_mstr_.php"
        $spec_file3 = "js.php"
        

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_dir
}