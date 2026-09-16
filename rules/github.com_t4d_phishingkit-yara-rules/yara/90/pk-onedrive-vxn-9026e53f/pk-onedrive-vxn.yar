rule PK_OneDrive_vxn : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-27"
        comment = "Phishing Kit - OneDrive - 'From: VXN@$hostname'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "home"
                $spec_file = "index_offpass_invalid.php"
        $spec_file2 = "index_otherinvalid.php"
        $spec_file3 = "vxn_off.php"
	    $spec_file4 = "vxn_other_invalid.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_dir and 
        all of ($spec_file*)
}