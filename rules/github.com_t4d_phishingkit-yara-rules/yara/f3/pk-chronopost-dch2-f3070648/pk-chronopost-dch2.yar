rule PK_Chronopost_dch2 : Chronopost
{
    meta:
        description = "Phishing Kit impersonating Chronopost"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-13"
        comment = "Phishing Kit - Chronopost - 'DCH Coder'"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_dir = "sourceApp"
                $spec_file = "chronopost_tours_03712200_113425863.jpg"
        $spec_file1 = "remettions-page.php"
        $spec_file2 = "engagement-page.php"
        $spec_file3 = "funciones.php"

    condition:
                uint32(0) == 0x04034b50 and 
	   $local_file and 
	   $spec_dir and 
	   all of ($spec_file*)
}