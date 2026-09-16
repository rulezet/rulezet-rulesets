rule PK_MailVerif_cnmail : MailVerif
{
    meta:
        description = "Phishing Kit harvesting e-mail addresses passwords"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-02"
        comment = "Phishing Kit - MailVerif - '$domain=cnmail'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "files"
                $spec_file = "x3d.php"
        $spec_file2 = "boxMrenewal.php"
        $spec_file3 = "boxMe.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3 and 
        $spec_dir
}