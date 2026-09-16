rule PK_Excel_olux : Excel
{
    meta:
        description = "Phishing Kit impersonating Excel page"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-01-07"
        comment = "Phishing Kit - Excel - by 'ICQ:724691041 (olux)'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "wait.php"
        $spec_file2 = "bizmail.php"
        $spec_file3 = "remove.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3
	}