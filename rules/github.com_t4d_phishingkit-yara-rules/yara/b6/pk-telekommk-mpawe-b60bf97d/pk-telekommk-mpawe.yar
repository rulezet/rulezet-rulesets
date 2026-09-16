rule PK_TelekomMK_MPAWE : Telekom_MK
{
    meta:
        description = "Phishing Kit impersonating Telekom MK"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2019-12-13"
        comment = "Phishing Kit - Telekom MK - MPawe"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "mpaweskd" nocase
        $spec_file2 = "jwqop.jpg"
        $spec_file3 = "thomemk.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3
}