rule PK_WellsFargo_anoxyty : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-20"
        comment = "Phishing Kit - Wells Fargo - '[ WellsFargo By Anoxyty | ]'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "secure"
                $spec_file = "carrz.php"
        $spec_file2 = "billres.php"
        $spec_file3 = "scrmderrs.php"
        $spec_file4 = "websafed.php"
        $spec_file5 = "yours.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                all of ($spec_file*)
}