rule PK_FreeMobile_ghaz : FreeMobile_ghaz
{
    meta:
        description = "Phishing Kit impersonating FreeMobile"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2019-12-28"
        comment = "Phishing kit impersonating FreeMobile - 'ghaz' version"  

    strings:
                $local_file = { 50 4b 03 04 }
        $spec_file = "ghaz.php"
        $spec_dir = "freemobile" nocase

    condition:
                uint32(0) == 0x04034b50 and
                $local_file and
                $spec_file and
                $spec_dir
}