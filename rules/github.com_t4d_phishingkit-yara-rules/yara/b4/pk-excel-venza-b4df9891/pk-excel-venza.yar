rule PK_Excel_venza : Excel
{
    meta:
        description = "Phishing Kit impersonating Excel page"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-02"
        comment = "Phishing Kit - Excel - 'CrEaTeD bY VeNzA'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "video"
                $spec_file = "next.php"
        $spec_file2 = "excel-white.png"
        $spec_file3 = "excel.mp4"
        $spec_file4 = "email.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}