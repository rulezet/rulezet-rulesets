rule PK_FedEx_ch : FedEx
{
    meta:
        description = "Phishing Kit impersonating FedEx"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-08-30"
        comment = "Phishing Kit - FedEx - 'targeting CH'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "files"
                $spec_file = "confirmation.html"
        $spec_file2 = "info.html"
        $spec_file3 = "sms.html"
        $spec_file4 = "tracking.png"
        $spec_file5 = "letter fedex sms.txt"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}