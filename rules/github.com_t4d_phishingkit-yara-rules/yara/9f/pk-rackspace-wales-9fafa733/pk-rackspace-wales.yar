rule PK_Rackspace_wales : Rackspace
{
    meta:
        description = "Phishing Kit impersonating Rackspace"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-04"
        comment = "Phishing Kit - Rackspace - 'Created By wales'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "rackspaceauto"
                $spec_file = "index.php"
        $spec_file2 = "log.php"
        $spec_file3 = "login.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_dir
}