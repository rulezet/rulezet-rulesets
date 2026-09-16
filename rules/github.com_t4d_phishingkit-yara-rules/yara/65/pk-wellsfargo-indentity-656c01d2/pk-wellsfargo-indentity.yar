rule PK_WellsFargo_indentity : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-09-29"
        comment = "Phishing Kit - Wells Fargo - 'WELLSFARGO ScamPage By GreyHatPakistan' and 'WELLSFARGO Indentity'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "processing"
        $spec_dir2 = "mrknowsall"
                $spec_file = "indentity.php"
        $spec_file2 = "ssn&dob.php"
        $spec_file3 = "selfie.php"
        $spec_file4 = "mrknowsall.php"
        $spec_file5 = "wf.gif"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}