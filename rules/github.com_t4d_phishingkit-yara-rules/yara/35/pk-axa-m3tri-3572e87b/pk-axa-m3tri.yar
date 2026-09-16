rule PK_AXA_m3tri : AXA
{
    meta:
        description = "Phishing Kit impersonating AXA insurance"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-03-17"
        comment = "Phishing Kit - AXA - 'Coded by METRI'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "M3tri-hash-bots"
        $spec_dir2 = "Xa_files"
                $spec_file = "Xa-infos.php"
        $spec_file2 = "cn-ajax.php"
        $spec_file3 = "infos.js"
        $spec_file4 = "PMT.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}