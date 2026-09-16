rule PK_PNC_eo : PNC
{
    meta:
        description = "Phishing Kit impersonating PNC online bank"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2022-11-01"
        comment = "Phishing Kit - PNC - 'newrepnceo'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "database"
        $spec_dir1 = "system"
        $spec_dir2 = "third_party"
                $spec_file = "blocker.php"
        $spec_file2 = "cazanova_helper.php"
        $spec_file3 = "authen.php"
        $spec_file4 = "sitekey.php"
        $spec_file5 = "2134651.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}