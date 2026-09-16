rule PK_FirstAmerican_jasper2 : FirstAmerican
{
    meta:
        description = "Phishing Kit impersonating First American insurance"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-05-04"
        comment = "Phishing Kit - First American - '-Created by JaSpEr-'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "id.php"
        $spec_file2 = "Error-costing.php"
        $spec_file3 = "index.htm"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*)
}