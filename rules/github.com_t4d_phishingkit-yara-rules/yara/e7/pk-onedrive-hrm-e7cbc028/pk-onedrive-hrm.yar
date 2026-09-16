rule PK_OneDrive_hrm : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-29"
        comment = "Phishing Kit - OneDrive - 'Scripted by HRM'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "image"
                $spec_file = "ink.php"
        $spec_file2 = "style.css"
        $spec_file3 = "Jr6ZeZQ.gif"
	    $spec_file4 = "02Etp5S4bK904LpzJzjD8eA-7.jpg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_dir and 
        all of ($spec_file*)
}