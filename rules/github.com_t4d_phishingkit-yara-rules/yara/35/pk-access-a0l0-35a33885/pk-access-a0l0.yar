rule PK_Access_a0l0 : Access
{
    meta:
        description = "Phishing Kit impersonating Access Bank"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-08-29"
        comment = "Phishing Kit - Access - 'From: a0l0'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "files"
                $spec_file = "index1.php"
        $spec_file2 = "i.php"
        $spec_file3 = "ii.php"
        $spec_file4 = "accountAssociationValidationModal.js"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}