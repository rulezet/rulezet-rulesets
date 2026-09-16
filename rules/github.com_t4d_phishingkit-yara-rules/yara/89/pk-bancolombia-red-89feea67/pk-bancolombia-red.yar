rule PK_Bancolombia_red : Bancolombia
{
    meta:
        description = "Phishing Kit impersonating Bancolombia"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-09-22"
        comment = "Phishing kit impersonating Bancolombia - use of multiple files named 'red..."        

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "index2_files"
        $spec_file = "desbloqueo.php"
        $spec_file2 = "VALIDATOR_EM_PH2.php"
        $spec_file3 = "redxxx.html"
        $spec_file4 = "login_SVP_BC_zonaA.html"

    condition:
                uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
                all of ($spec_file*)
}