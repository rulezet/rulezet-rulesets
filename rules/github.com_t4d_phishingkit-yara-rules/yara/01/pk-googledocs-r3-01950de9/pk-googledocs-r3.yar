rule PK_GoogleDocs_r3 : GoogleDocs
{
    meta:
        description = "Phishing Kit impersonating Google docs"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-26"
        comment = "Phishing Kit - Google Docs"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "images"
                $spec_file = "docmsg.htm"
        $spec_file2 = "mail.php"
        $spec_file3 = "GmailTransparent1.png"
        $spec_file4 = "R3WinLive1033.css"
        $spec_file5 = "checkmark.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}