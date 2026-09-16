rule PK_Optimum_yochi : Optimum
{
    meta:
        description = "Phishing Kit impersonating Optimum.net"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-06-02"
        comment = "Phishing Kit - Optimum - 'From: YoCHI <yochmnet@yochzon.xyz>'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "admin"
        $spec_dir2 = "fad58"
        $spec_dir3 = "cc0d1ffd9"
                $spec_file = "882c.php"
        $spec_file2 = "yo.txt"
        $spec_file3 = "upp.php"
        $spec_file4 = "icon_optstore.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}