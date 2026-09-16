rule PK_WeTransfer_only4biz : WeTransfer
{
    meta:
        description = "Phishing Kit impersonating WeTransfer"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-04"
        comment = "Phishing Kit - WeTransfer - '*** Skype: only4biz *****'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "assets"
                $spec_file = "finish1.php"
        $spec_file2 = "login4841.php"
        $spec_file3 = "wrong.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                $spec_file and
        $spec_file2 and
        $spec_file3
}