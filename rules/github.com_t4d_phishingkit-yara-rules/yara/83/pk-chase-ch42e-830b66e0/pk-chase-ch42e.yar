rule PK_Chase_Ch42e : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-09-25"
        comment = "Phishing Kit - Chase Bank - From: customer@Ch42e.org"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_dir = "ip_files"
                $spec_file = "process4.php"
        $spec_file2 = "emaila.php"
        $spec_file3 = "acct.php"

    condition:
                uint32(0) == 0x04034b50 and 
	   $local_file and 
	   $spec_dir and 
	   $spec_file and 
	   $spec_file2 and
       $spec_file3
}