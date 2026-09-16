rule PK_NatWest_kts : NatWest
{
    meta:
        description = "Phishing Kit impersonating NatWest bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-20"
        comment = "Phishing Kit - NatWest - 'page made by KTS team'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "safeguard"
                $spec_file = "php.php"
        $spec_file2 = "man.txt"
        $spec_file3 = "cloaker.php"
        $spec_file4 = "sign.sh"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                all of ($spec_file*)
}