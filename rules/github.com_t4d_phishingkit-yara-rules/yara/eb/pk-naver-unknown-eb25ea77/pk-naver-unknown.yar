rule PK_Naver_unknown : Naver
{
    meta:
        description = "Phishing Kit impersonating Naver Corp."
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-22"
        comment = "Phishing Kit - Naver - 'Created BY Unknown'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "nvv.php"
        $spec_file2 = "esss.php"
        $spec_file3 = "next.php"
        $spec_file4 = "favicon.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*)
}