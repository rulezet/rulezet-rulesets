rule PK_IRS_sirus : IRS
{
    meta:
        description = "Phishing Kit impersonating US Internal Revenue Service"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-06-11"
        comment = "Phishing Kit - IRS - 'Created BY SIRUS BLACK'"

    strings:
        $zip_file = { 50 4b 03 04 }
                $spec_dir = "mainMenuUSIRS_data"
                $spec_file1 = "login.php"
        $spec_file2 = "login_theme2.css"
        $spec_file3 = "mainMenuUSIRS.html"
        $spec_file4 = "wtid.js"


    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and 
        all of ($spec_file*)
}