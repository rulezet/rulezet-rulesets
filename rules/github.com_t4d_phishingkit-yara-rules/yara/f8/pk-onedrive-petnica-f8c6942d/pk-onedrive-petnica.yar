rule PK_OneDrive_petnica : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-04-05"
        comment = "Phishing Kit - OneDrive - With a lots of 'petnica' named files"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "petnica.php"
        $spec_file2 = "petnica.js"
        $spec_file3 = "petnica.css"
	    $spec_file4 = "petnica3.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_file*)
}