rule PK_WeTransfer_l0gin : WeTransfer
{
    meta:
        description = "Phishing Kit impersonating WeTransfer"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-16"
        comment = "Phishing Kit - WeTransfer - use of filename l0gin.php"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "bg1.png"
        $spec_file2 = "l0gin.php"
        $spec_file3 = "l0gin2nd.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3
}