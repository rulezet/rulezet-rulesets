rule PK_Facebook_tigari : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-03-29"
        comment = "Phishing Kit - Facebook - 'file_put_contents tigari.txt'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "sign_in_files"
                $spec_file = "finishlogin.php"
        $spec_file2 = "gateway.php"
        $spec_file3 = "sign_in.html"
        $spec_file4 = "newlogo.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}