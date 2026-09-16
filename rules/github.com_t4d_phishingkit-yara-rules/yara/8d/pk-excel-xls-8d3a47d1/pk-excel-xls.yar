rule PK_Excel_xls : Excel
{
    meta:
        description = "Phishing Kit impersonating Excel page"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-04-13"
        comment = "Phishing Kit - Excel - 'From: XLS'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "go.php"
        $spec_file2 = "po.html"
        $spec_file3 = "xls.php"
        $spec_file4 = "server.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and 
                all of ($spec_file*)
}