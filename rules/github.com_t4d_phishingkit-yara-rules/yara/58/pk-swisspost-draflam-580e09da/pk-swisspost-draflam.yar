rule PK_SwissPost_draflam : SwissPost
{
    meta:
        description = "Phishing Kit impersonating Swiss Post"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-20"
        comment = "Phishing Kit - Swiss Post - Containing DRAFLAM directory"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "DRAFLAM"
        $spec_dir2 = "siftA"
        $spec_dir3 = "X911"
                $spec_file = "COUNTRY.php"
        $spec_file2 = "TELEGRMAT.php"
        $spec_file3 = "911.php"
        $spec_file4 = "Loading.php"
        $spec_file5 = "DISCOVER.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}