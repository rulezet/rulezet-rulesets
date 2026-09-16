rule PK_AlaskaUSA_metoll : AlaskaUSA
{
    meta:
        description = "Phishing Kit impersonating Alaska USA Federal Credit Union"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-05-22"
        comment = "Phishing Kit - AlaskaUSA - '-+ MeToll +-'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "1.php"
        $spec_file2 = "2.php"
        $spec_file3 = "security.php"
        $spec_file31 = "pagepage.html"
        $spec_file4 = "AkusaIcon.ttf"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and 
        $spec_file2 and 
        ($spec_file3 or $spec_file31) and 
        $spec_file4
}