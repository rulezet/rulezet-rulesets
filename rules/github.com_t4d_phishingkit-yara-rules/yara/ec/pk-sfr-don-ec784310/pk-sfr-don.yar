rule PK_SFR_don : SFR
{
    meta:
        description = "Phishing Kit impersonating SFR Mail"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-05"
        comment = "Phishing Kit - SFR Mail - '-Coded by don-'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "SFRMailmail_files"
                $spec_file = "SFRMailmail.htm"
        $spec_file2 = "mire-sfr-mail.jpg"
        $spec_file3 = "HSFR_ec2-1.png"
        $spec_file4 = "style-responsive.css"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                $spec_file and
        $spec_file2 and
        $spec_file3 and 
        $spec_file4
}