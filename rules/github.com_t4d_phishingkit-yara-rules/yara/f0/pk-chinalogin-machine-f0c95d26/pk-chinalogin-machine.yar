rule PK_ChinaLogin_Machine : chinese_Email_verification
{
    meta:
        description = "Phishing Kit stealing email credentials in chinese"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-16"
        comment = "Phishing Kit - Email Verification - 'Scripted by Machine'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "25GB"
                $spec_file = "Message.txt"
        $spec_file2 = "none.php"
        $spec_file3 = "error.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                $spec_file and
        $spec_file2 and
        $spec_file3
}