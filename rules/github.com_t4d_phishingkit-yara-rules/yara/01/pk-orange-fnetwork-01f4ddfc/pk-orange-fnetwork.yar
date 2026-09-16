rule PK_Orange_fnetwork : Orange
{
    meta:
        description = "Phishing Kit impersonating Orange"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-18"
        comment = "Phishing Kit - Orange - 'BY Mr.fnetwork'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Identifiez-vous avec votre compte Orange_fichiers"
        $spec_dir2 = "password_fichiers"
                $spec_file = "finish.php"
        $spec_file2 = "password.php"
        $spec_file3 = "pubads_impl_2020120701.js"
	    $spec_file4 = "567x302_OBANK_Levier01_PUSH_20201109a.jpg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and 
	    all of ($spec_dir*)
}