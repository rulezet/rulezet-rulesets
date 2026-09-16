rule PK_DropBox_lut : Dropbox
{
    meta:
        description = "Phishing Kit impersonating DropBox"
        licence = ""
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-03-26"
        comment = "Phishing Kit - DropBox - '$from = Lut@Tech.com'"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_dir = "Drop_files"
        $spec_dir2 = "a_data"
                $spec_file = "a.htm"
        $spec_file2 = "bat.js"
        $spec_file3 = "dismiss-cross-vflIlGysZ.png"
        $spec_file4 = "keep-your-photos-safe-vflZe9PHC.png"

    condition:
                uint32(0) == 0x04034b50 and
        $local_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}