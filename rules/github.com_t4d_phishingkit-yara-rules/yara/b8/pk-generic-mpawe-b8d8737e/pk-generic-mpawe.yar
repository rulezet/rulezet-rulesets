rule PK_Generic_MPAWE : Mpawe_Generic
{
    meta:
        description = "Phishing Kit - MPawe"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2019-12-13"
        comment = "Phishing Kit - MPawe"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "mpaweskd" nocase
        $spec_file2 = "jwqop.jpg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2
}