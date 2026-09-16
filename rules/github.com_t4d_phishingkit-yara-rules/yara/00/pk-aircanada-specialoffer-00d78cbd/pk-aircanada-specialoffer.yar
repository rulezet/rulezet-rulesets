rule PK_AirCanada_specialoffer : Air Canada
{
    meta:
        description = "Phishing Kit impersonating Air Canada"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://twitter.com/Stalkphish_io/status/1486793216309538823"
        date = "2022-01-27"
        comment = "Phishing Kit - Air Canada - specialoffer directory"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "specialoffer"
                $spec_file = "completed.html"
        $spec_file2 = "select2-dux.css"
        $spec_file3 = "select2x2.png"
        $spec_file4 = "s3.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}