rule PK_NAB_echovsl : NAB
{
    meta:
        description = "Phishing Kit impersonating National Australia Bank (NAB)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-10-08"
        comment = "Phishing kit - NAB - 'TELEGRAM: ECHOVSL'"        

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "script"
                $spec_file = "fxker.php"
        $spec_file2 = "auth3.html"
        $spec_file3 = "edit.php"
        $spec_file4 = "security.html"
        $spec_file5 = "star-big.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}