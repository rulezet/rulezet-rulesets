rule PK_Chase_spox : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://blog.sucuri.net/2020/07/spox-phishing-kit-harvests-chase-bank-credentials.html"
        date = "2021-05-05"
        comment = "Phishing Kit - Chase Bank - 'C0d3d by Spox_dz'"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_dir = "Spox"
                $spec_file = "YOUR-CONFIG.php"
        $spec_file2 = "Bot-Spox.php"
        $spec_file3 = "chasefavicon.ico"
        $spec_file4 = "Fuck-you.php"

    condition:
                uint32(0) == 0x04034b50 and 
	   $local_file and 
	   $spec_dir and 
	   all of ($spec_file*)
}