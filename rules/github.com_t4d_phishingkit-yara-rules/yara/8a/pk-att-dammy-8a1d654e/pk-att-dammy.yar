rule PK_ATT_dammy : ATandT
{
    meta:
        description = "Phishing Kit impersonating ATandT"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-12"
        comment = "Phishing Kit - ATandT - 'Hacked By Opa Dammy'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "Team.php"
        $spec_file2 = "Indexxatt.htm"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2
}