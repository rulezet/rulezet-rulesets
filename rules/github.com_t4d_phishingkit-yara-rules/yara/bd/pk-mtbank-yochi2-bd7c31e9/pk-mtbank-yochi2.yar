rule PK_MTBank_yochi2 : MT_Bank
    {
        meta:
            description = "Phishing Kit impersonating M&T Bank"
            licence = "AGPL-3.0"
            author = "Thomas 'tAd' Damonneville"
            reference = ""
            date = "2025-03-02"
            comment = "Phishing Kit - M&T Bank - 'From: YoCHI'"

        strings:
                        $zip_file = { 50 4b 03 04 }
            $spec_dir = "autob"
            $spec_dir1 = "admin"
                        $spec_file = "bts2.php"
            $spec_file2 = "logov.php"
            $spec_file3 = "susps.php"
            $spec_file4 = "refspam.php"
            $spec_file5 = "mtb-logo.svg"

        condition:
                        uint32(0) == 0x04034b50 and
                        $zip_file and
            all of ($spec_dir*) and 
                        all of ($spec_file*) 
    }