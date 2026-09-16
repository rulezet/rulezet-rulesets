rule PK_RobinsFCU_gram : RobinsFCU
{
    meta:
        description = "Phishing Kit impersonating Robins Financial Credit Union"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-05-05"
        comment = "Phishing Kit - RobinsFCU - 'using $Gram variable name'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Assets"
        $spec_dir1 = "user"
                $spec_file = "verifylogin.php"
        $spec_file2 = "process1.php"
        $spec_file3 = "ServerData.php"
        $spec_file4 = "edit.php"
        $spec_file5 = "FraudAlertsPanelImages.png.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}