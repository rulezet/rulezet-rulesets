rule PK_MTB_xx : MT_Bank
{
    meta:
        description = "Phishing Kit impersonating M&T Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-12"
        comment = "Phishing Kit - M&T Bank - 'xx.php'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "Hajjjjerr.htm"
        $spec_file2 = "xx.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 
}