rule PK_Ourtime_mmxq : Ourtime
{
    meta:
        description = "Phishing Kit - OurTime.com - mmxq"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2019-12-16"
        comment = "Phishing Kit - OurTime.com - mmxq"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "mmxq.html"
        $spec_file2 = "wp-root.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2
}