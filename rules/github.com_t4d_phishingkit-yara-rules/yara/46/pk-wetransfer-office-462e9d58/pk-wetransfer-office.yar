rule PK_WeTransfer_office : WeTransfer
{
    meta:
        description = "Phishing Kit impersonating WeTransfer"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-04"
        comment = "Phishing Kit - WeTransfer - '$subject = New Wetransfer Office'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "login"
                $spec_file = "core.php"
        $spec_file1 = "postLogin.php"
        $spec_file2 = "downloads.php"
        $spec_file3 = "robots.txt"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_dir and 
        all of ($spec_file*)
}