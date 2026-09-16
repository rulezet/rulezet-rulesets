rule PK_OneDrive_ivano : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-05-26"
        comment = "Phishing Kit - OneDrive - '-+ Created in Ivano+-'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "prefetch_data"
                $spec_file = "segn.php"
        $spec_file2 = "vote2.php"
        $spec_file3 = "indexx.php"
	    $spec_file4 = "GetDetail.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_dir and 
        all of ($spec_file*)
}