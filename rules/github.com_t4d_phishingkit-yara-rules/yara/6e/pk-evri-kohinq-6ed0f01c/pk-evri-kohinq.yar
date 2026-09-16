rule PK_Evri_kohinq : Evri
{
    meta:
        description = "Phishing Kit impersonating Evri"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-10"
        comment = "Phishing Kit - Evri - 'Kohinq - NEW DATAs' - v1.32"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "remote"
        $spec_dir2 = "logs"
                $spec_file = "dataformat2.log"
        $spec_file2 = "track.php"
        $spec_file3 = "CONFIG.php"
        $spec_file4 = "netcraft_check.php"
        $spec_file5 = "ReferralSpamDetect.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}