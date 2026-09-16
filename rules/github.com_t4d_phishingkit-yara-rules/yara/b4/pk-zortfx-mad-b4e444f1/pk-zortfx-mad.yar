rule PK_ZortFX_mad : ZortFX
{
    meta:
        description = "Phishing Kit impersonating ZortFX Market"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-24"
        comment = "Phishing Kit - ZortFX - '--Mad--'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Web Client Sign In_files"
        $spec_file = "verified.php"
        $spec_file2 = "upgradesuccessful.html"
        $spec_file3 = "zi.png"
        $spec_file4 = "commonloginzhtmlskin.css"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}