rule PK_CitadelCU_guard : CitadelCU
{
    meta:
        description = "Phishing Kit impersonating Citadel Credit Union"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-06-10"
        comment = "Phishing Kit - CitadelCU - using 'Guard' directory name"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Guard"
        $spec_dir2 = "ExperienceForms"
        $spec_dir3 = "Meta"
                $spec_file = "cmdzamp.php"
        $spec_file2 = "demonTest.php"
        $spec_file3 = "relogin.php"
        $spec_file4 = "ChangeMe.php"
        $spec_file5 = "call-citadel-credit-union.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
        all of ($spec_file*)
}