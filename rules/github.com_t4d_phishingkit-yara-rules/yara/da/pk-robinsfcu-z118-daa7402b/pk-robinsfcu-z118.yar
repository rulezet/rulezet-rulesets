rule PK_RobinsFCU_z118 : RobinsFCU
{
    meta:
        description = "Phishing Kit impersonating Robins Federal Credit Union"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-02-04"
        comment = "Phishing Kit - Robins Federal Credit Union - '$Z118_EMAIL'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "functions"
        $spec_dir2 = "grabber"
                $spec_file = "fullz.php"
        $spec_file2 = "CARD.php"
        $spec_file3 = "onetime.php"
        $spec_file4 = "Dila_DZ.php"
        $spec_file5 = "logo_large-e51445d8eeb9217b6aea61bb2b2af5dc.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}