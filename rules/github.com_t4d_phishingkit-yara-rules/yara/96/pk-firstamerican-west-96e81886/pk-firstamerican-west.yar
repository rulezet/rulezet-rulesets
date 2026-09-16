rule PK_FirstAmerican_west : FirstAmerican
{
    meta:
        description = "Phishing Kit impersonating First American insurance"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-14"
        comment = "Phishing Kit - First American - 'From: $domain<west>'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Login - myFirstAm_files"
                $spec_file = "email.php"
        $spec_file2 = "index.html"
        $spec_file3 = "geoplugin.class.php"
        $spec_file4 = "Office365-720x360px.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}