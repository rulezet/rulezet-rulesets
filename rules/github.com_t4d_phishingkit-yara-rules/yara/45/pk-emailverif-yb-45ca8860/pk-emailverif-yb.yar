rule PK_EmailVerif_yb : Email_verification
{
    meta:
        description = "Phishing Kit stealing email credentials"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-13"
        comment = "Phishing Kit - Email Verification - 'Created By yb'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "files"
                $spec_file = "Message.txt"
        $spec_file2 = "post.php"
        $spec_file3 = "pass.php"
        $spec_file4 = "connect.html"
        $spec_file5 = "id.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                all of ($spec_file*)
}