rule PK_Chase_xsniper : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://lukeleal.com/research/posts/elzero-x-sniper-phishing-kits/"
        date = "2022-02-02"
        comment = "Phishing Kit - Chase Bank - 'Copyright all Reserved to X-Sniper Page'"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_dir = "X-Sniper"
        $spec_dir2 = "ElZero"
                $spec_file = "doubleEmailAccess.php"
        $spec_file2 = "ElZero.php"
        $spec_file3 = "X-sniper2.php"
        $spec_file4 = "someBots.php"

    condition:
                uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}