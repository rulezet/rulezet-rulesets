rule PK_BECU_praga : BECU
{
    meta:
        description = "Phishing Kit impersonating BECU bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-03"
        comment = "Phishing Kit - BECU - '&id=$praga$praga'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "images"
                $spec_file = "next2.php"
        $spec_file2 = "step3.php"
        $spec_file3 = "btn2.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                $spec_file and
        $spec_file2 and
        $spec_file3
}