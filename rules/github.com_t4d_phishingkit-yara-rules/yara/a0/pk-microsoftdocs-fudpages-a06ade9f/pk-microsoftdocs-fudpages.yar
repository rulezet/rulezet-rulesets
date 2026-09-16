rule PK_MicrosoftDocs_fudpages : Microsoft
{
    meta:
        description = "Phishing Kit impersonating Microsoft Docs"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-26"
        comment = "Phishing Kit - Microsoft - '- FUDPAGEs [.] RU -'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "assets"

                $spec_file = "index-2.php"
        $spec_file2 = "index2.php"
        $spec_file3 = "processor.php"
        $spec_file4 = "theDocs.all.min.css"
        $spec_file5 = "word.png"
        $spec_file6 = "theDocs.all.min.js"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}