rule PK_Maersk_only4biz : Maersk
{
    meta:
        description = "Phishing Kit impersonating Maersk"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-02-02"
        comment = "Phishing Kit - Maersk - '- only4biz.org -'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "images"
                $spec_file = "logon.php"
        $spec_file2 = "send.php"
        $spec_file3 = "robot.txt"
        $spec_file4 = "maersk.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                all of ($spec_file*)
}