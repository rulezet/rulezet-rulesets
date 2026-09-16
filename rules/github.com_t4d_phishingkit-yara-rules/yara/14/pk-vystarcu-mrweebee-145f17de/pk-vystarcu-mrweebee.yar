rule PK_VystarCU_mrweebee : VystarCU
{
    meta:
        description = "Phishing Kit impersonating VYSTAR CU"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-30"
        comment = "Phishing Kit - Vystar CU - 'MRWEEBEE  | VYSTAR CREDIT UNION'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "settings"
        $spec_dir2 = "Logs"
                $spec_file = "session_emma.php"
        $spec_file2 = "session_personal.php"
        $spec_file3 = "settings.php"
        $spec_file4 = "verify_session_emma.php"
        $spec_file5 = "Vystar_New_Logo.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}