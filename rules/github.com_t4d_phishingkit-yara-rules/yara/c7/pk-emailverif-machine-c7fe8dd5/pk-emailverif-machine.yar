rule PK_EmailVerif_Machine : Email_verification
{
    meta:
        description = "Phishing Kit stealing email credentials"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-09-25"
        comment = "Phishing Kit - Email Verification - 'Scripted by Machine'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "deactivation"
                $spec_file = "Message.txt"
        $spec_file2 = "appstore.jpg"
        $spec_file3 = "googleplay.png"
        $spec_file4 = "error.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                $spec_file and
        $spec_file2 and
        $spec_file3 and
	    $spec_file4
}