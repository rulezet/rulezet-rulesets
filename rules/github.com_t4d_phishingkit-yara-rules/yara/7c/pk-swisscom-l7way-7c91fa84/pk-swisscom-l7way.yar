rule PK_Swisscom_l7way : Swisscom
{
    meta:
        description = "Phishing Kit impersonating Swisscom"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-11"
        comment = "Phishing Kit - Swisscom - by 'l7way'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "log"
                $spec_file = "scamti.css"
        $spec_file2 = "dd.php"
        $spec_file3 = "cc.php"
        $spec_file4 = "smserror.php"


    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}