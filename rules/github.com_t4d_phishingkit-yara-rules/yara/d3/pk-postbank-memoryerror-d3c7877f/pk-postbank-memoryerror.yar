rule PK_Postbank_memoryerror : Postbank
{
    meta:
        description = "Phishing Kit impersonating Postbank"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-03-02"
        comment = "Phishing Kit - Postbank - 'Main Author: MemoryError'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "victims"
        $spec_dir1 = "3-D Secure_files"
        $spec_dir2 = "Loginloading_files"
                $spec_file = "LoginPASS.html"
        $spec_file2 = "3-D Secure.html"
        $spec_file3 = "botMother.php"
        $spec_file4 = "0om4.php"
        $spec_file5 = "account.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}