rule PK_SwissPost_Bankia : SwissPost
{
    meta:
        description = "Phishing Kit impersonating Swiss Post"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-09-20"
        comment = "Phishing Kit - Swiss Post - by 'Adem'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "BANKIA_files"
                $spec_file = "2038_logo.gif"
        $spec_file2 = "pwdbaseud.js.download"
        $spec_file3 = "sms/id.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        $spec_dir
}