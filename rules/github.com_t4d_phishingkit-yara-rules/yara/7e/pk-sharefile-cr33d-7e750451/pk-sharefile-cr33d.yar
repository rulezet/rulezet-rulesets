rule PK_ShareFile_CR33D : ShareFile
{
    meta:
        description = "Phishing Kit impersonating Citrix ShareFile"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-16"
        comment = "Phishing Kit - Citrix ShareFile - by 'CR33D'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "htaccess"
        $spec_file2 = "456edi675cityd56idi76r.php"
        $spec_file3 = "oc8743rg387efg9823983e.php"
        $spec_file4 = "f8394rf99fh98h98h3hf3.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3 and 
        $spec_file4
}