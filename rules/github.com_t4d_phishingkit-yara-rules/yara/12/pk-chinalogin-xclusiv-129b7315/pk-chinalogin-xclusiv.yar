rule PK_ChinaLogin_xclusiv : chinese_Email_verification
{
    meta:
        description = "Phishing Kit stealing email credentials in chinese"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-19"
        comment = "Phishing Kit - Email Verification - 'Xclusiv-3D-Logs'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "files"
                $spec_file = "enx.php"
        $spec_file2 = "sxc.php"
        $spec_file3 = "post1.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                $spec_file and
        $spec_file2 and
        $spec_file3
}