rule PK_RoyalMail_RMtaxClaim : RoyalMail
{
    meta:
        description = "Phishing Kit impersonating RoyalMail"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://twitter.com/JCyberSec_/status/1392112310785875988"
        date = "2021-05-11"
        comment = "Phishing Kit - RoyalMail - RMtaxClaim (@JCyberSec_)"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "mustangostang"
                $spec_file = "check.php"
        $spec_file2 = "payment.php"
        $spec_file3 = "intro.php"
        $spec_file4 = "control.php"
        $spec_file5 = "visits.txt"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}