rule PK_FedEx_petter : FedEx
{
    meta:
        description = "Phishing Kit impersonating FedEx"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-08-22"
        comment = "Phishing Kit - FedEx - '[+] fedex petter FULLZ [+]'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "system"
        $spec_dir2 = "fedex"
                $spec_file = "confirmed.php"
        $spec_file2 = "jeansms2.php"
        $spec_file3 = "tlgrm.php"
        $spec_file4 = "fdx.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}