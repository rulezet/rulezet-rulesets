rule PK_Jenis_GhostMode : Jenis
{
    meta:
        description = "Phishing Kit impersonating Jeni's Icecream"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://twitter.com/Stalkphish_io/status/1468487303001694208"
        date = "2021-12-08"
        comment = "Phishing Kit - Jeni's - 'GhostMode'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "jenis_files"
                $spec_file = "jenis.png"
        $spec_file2 = "result.php"
        $spec_file3 = "jenis.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                all of ($spec_file*)
}