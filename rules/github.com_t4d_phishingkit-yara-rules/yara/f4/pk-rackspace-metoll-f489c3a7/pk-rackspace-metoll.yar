rule PK_Rackspace_Metoll : Rackspace
{
    meta:
        description = "Phishing Kit impersonating Rackspace"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-10-22"
        comment = "Phishing Kit - Rackspace - '+ MeToll +'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "image"
                $spec_file = "jfk.php"
        $spec_file2 = "rracspc.html"
        $spec_file3 = "c3.jpg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        $spec_dir
}