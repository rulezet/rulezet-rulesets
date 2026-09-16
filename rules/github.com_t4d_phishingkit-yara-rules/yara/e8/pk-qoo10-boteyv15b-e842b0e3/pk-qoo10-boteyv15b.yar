rule PK_Qoo10_boteyV15b : Qoo10
{
    meta:
        description = "Phishing Kit impersonating Qoo10"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-21"
        comment = "Phishing Kit - Qoo10 - 'BOTeye v1.5 Beta - Made by Cyborg99'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "picture_library"
        $spec_dir1 = "res"
                $spec_file = "security.html"
        $spec_file2 = "log5.php"
        $spec_file3 = "verification-loc=en_SG.requester=identity.html"
        $spec_file4 = "submission.html"
        $spec_file5 = "thank-you.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}