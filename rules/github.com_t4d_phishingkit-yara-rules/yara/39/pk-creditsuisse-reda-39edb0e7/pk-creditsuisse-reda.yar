rule PK_CreditSuisse_reda : CreditSuisse
{
    meta:
        description = "Phishing Kit impersonating Credit Suisse bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-03-13"
        comment = "Phishing Kit - Credit Suisse - 'first_name: Reda'"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_dir = "queries"
        $spec_dir2 = "panel"
        $spec_dir3 = "prevents"
                $spec_file = "lo2.php"
        $spec_file2 = "handle_edit.php"
        $spec_file3 = "visitors.html"
        $spec_file4 = "date.png"

    condition:
                uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}