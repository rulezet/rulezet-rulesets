rule PK_Facebook_xsr : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-29"
        comment = "Phishing Kit - Facebook - 'This Phishing Page Has Powerd By XSR.404'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "static.xx.fbcdn.net"
                $spec_file = "QzsHSoWJZTl.css"
        $spec_file2 = "email.php"
        $spec_file3 = "Read Me!!.txt"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}