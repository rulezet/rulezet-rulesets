rule PK_Globalsources_Machine : Globalsources
{
    meta:
        description = "Phishing Kit impersonating GlobalSources"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-10"
        comment = "Phishing Kit - Globalsources - 'Scripted by Machine'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "GlobalSources"
                $spec_file = "index.html"
        $spec_file2 = "logo.jpg"
        $spec_file3 = "verify.php"
        $spec_file4 = "ray.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                $spec_file and
        $spec_file2 and
        $spec_file3 and
	    $spec_file4
}