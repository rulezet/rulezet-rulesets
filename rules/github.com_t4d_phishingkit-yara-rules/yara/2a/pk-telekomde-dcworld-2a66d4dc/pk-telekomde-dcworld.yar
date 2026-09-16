rule PK_TelekomDE_dcworld : TelekomDE
{
    meta:
        description = "Phishing Kit impersonating Telekom Deutschland GmbH"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2024-01-15"
        comment = "Phishing Kit - Telekom DE - 'Brought to you by dcworld'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "css"
                $spec_file = "confr.php"
        $spec_file2 = "translateelement.css"
        $spec_file3 = "sgh.txt"
        $spec_file4 = "translate_24dp.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}