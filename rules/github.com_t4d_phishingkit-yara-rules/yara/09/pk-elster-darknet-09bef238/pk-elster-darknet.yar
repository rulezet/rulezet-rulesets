rule PK_Elster_darknet : Elster
{
    meta:
        description = "Phishing Kit impersonating Elster tax office (DE)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-11-25"
        comment = "Phishing Kit - Elster - 'Collected by: DarkNet_v1'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Asstes"
        $spec_dir2 = "next_step"
        $spec_dir3 = "questions"
                $spec_file = "questiontan_page.php"
        $spec_file2 = "dbc.php"
        $spec_file3 = "fetch_victims_status.php"
        $spec_file4 = "anti7.php"
        $spec_file5 = "43417e64f90b21c1f999384b6a8f3d12.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}