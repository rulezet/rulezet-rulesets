rule PK_Ebay_isapi : EBay
{
    meta:
        description = "Phishing Kit impersonating Ebay"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-12"
        comment = "Phishing Kit - EBay - contain 'eBayISAPI.php' file" 

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "eBayISAPI.php"
        $spec_file1 = "act.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*)
}