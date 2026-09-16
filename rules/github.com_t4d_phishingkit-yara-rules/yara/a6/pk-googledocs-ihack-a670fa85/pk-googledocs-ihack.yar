rule PK_GoogleDocs_ihack : GoogleDocs
{
    meta:
        description = "Phishing Kit impersonating Google docs"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-06-22"
        comment = "Phishing Kit - by Ihack"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "google_data"
        $spec_dir2 = "index_files"
                $spec_file = "other.php"
        $spec_file2 = "gmail.php"
        $spec_file3 = "aol.php"
        $spec_file4 = "logo-rdc-header.png"
        $spec_file5 = "storage.swf"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of($spec_dir*) and 
                all of ($spec_file*)
}