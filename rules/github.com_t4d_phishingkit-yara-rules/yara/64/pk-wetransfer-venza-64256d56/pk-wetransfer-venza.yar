rule PK_WeTransfer_venza : WeTransfer
{
    meta:
        description = "Phishing Kit impersonating WeTransfer"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-31"
        comment = "Phishing Kit - WeTransfer - 'CrEaTeD bY VeNzA'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
        $spec_dir2 = "images"
                $spec_file = "telegram.php"
        $spec_file1 = "next.php"
        $spec_file2 = "email.php"
        $spec_file3 = "index.html"
        $spec_file4 = "video-02.mp4"
        $spec_file5 = "logo2.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_dir*) and 
        all of ($spec_file*)
}