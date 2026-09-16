rule PK_GovCA_krepto : GovCA
{
    meta:
        description = "Phishing Kit impersonating Canadian Government (CRA)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-13"
        comment = "Phishing kit - GovCA - 'From:Kr3pto'"        

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "page_l0gz"
        $spec_dir2 = "gateway_6GL7gpQHstQijU8N"
        $spec_dir3 = "visitor_l0gz"
                $spec_file = "mob_lock.php"
        $spec_file2 = "exit_channel.php"
        $spec_file3 = "_valvisitor.php"
        $spec_file4 = "netcraft_check.php"
        $spec_file5 = "wmms-blk.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}