rule PK_MTBank_msp : MT Bank
{
    meta:
        description = "Phishing Kit impersonating M&T Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-01-06"
        comment = "Phishing Kit - M&T Bank"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "passs.php"
        $spec_file2 = "succes.php"
        $spec_file3 = "credit-card-with-hook-mt2019.jpg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3
}