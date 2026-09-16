rule PK_AlturaCU_yunsun : AlturaCU
{
    meta:
        description = "Phishing Kit impersonating Robins Altura Credit Union"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2022-11-10"
        comment = "Phishing Kit - AlturaCU - 'TELEGRAM : @Yun_Sun'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "anti__boot"
        $spec_dir1 = "js"
                $spec_file = "access.php"
        $spec_file2 = "loading-3.php"
        $spec_file3 = "anti8.php"
        $spec_file4 = "test.css"
        $spec_file5 = "loogo.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}