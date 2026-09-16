rule PK_WeTransfer_dubby : WeTransfer
{
    meta:
        description = "Phishing Kit impersonating WeTransfer"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-08-23"
        comment = "Phishing Kit - WeTransfer - '-Created BY Dubby-'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "img"
                $spec_file = "bt.php"
        $spec_file1 = "index_.php"
        $spec_file2 = "2.jpg"
        $spec_file3 = "index.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_dir and 
        all of ($spec_file*)
}