rule PK_EarthLink_33flow : EarthLink
{
    meta:
        description = "Phishing Kit impersonating EarthLink"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-04-22"
        comment = "Phishing Kit - EarthLink - 'Created in 2020 [ Don  33flow ]'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "imgs"
                $spec_file = "delete.php"
        $spec_file2 = "_+--_=_.php"
        $spec_file3 = "elnk_logo.png"
        $spec_file4 = "_=+---+_=.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                all of ($spec_file*)
}