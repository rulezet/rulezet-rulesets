rule PK_DropBox_2023 : Dropbox
{
    meta:
        description = "Phishing Kit impersonating DropBox"
        licence = ""
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-07-20"
        comment = "Phishing Kit - DropBox - '2023dropbox'"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_dir = "images"
                $spec_file = "AOL.html"
        $spec_file2 = "001100110011yahoo.html"
        $spec_file3 = "success.php"
        $spec_file4 = "Outlookheader.png"

    condition:
                uint32(0) == 0x04034b50 and
        $local_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}