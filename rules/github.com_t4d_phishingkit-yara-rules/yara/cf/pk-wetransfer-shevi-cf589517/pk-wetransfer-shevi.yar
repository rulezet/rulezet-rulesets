rule PK_WeTransfer_shevi : WeTransfer
{
    meta:
        description = "Phishing Kit impersonating WeTransfer"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-04-28"
        comment = "Phishing Kit - WeTransfer - 'WEtransfer Logx CoDeD By Shevi'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "cgi"
                $spec_file = "loading.php"
        $spec_file1 = "loading.php"
        $spec_file2 = "timeout.php"
        $spec_file3 = "login6.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_dir and 
        all of ($spec_file*)
}