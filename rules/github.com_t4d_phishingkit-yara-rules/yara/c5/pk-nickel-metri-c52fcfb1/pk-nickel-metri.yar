rule PK_Nickel_metri : Nickel
{
    meta:
        description = "Phishing Kit impersonating Nickel"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.linkedin.com/feed/update/urn:li:activity:7197112043672416256"
        date = "2024-05-16"
        comment = "Phishing Kit - Nickel - 'Coded by METRI'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "nkl_files"
        $spec_dir2 = "rezult"
        $spec_dir3 = "visites"
                $spec_file = "nkl-infos.php"
        $spec_file2 = "M3tri-control.php"
        $spec_file3 = "Error.php"
        $spec_file4 = "HunterObfuscator.php"
        $spec_file5 = "nkl-otp.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}