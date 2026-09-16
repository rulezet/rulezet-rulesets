rule Mirai_2 : MALW
{
meta:
	description = "Mirai Variant 2"
	author = "Joan Soriano / @joanbtl"
	date = "2017-04-16"
	version = "1.0"
	MD5 = "0e5bda9d39b03ce79ab8d421b90c0067"
	SHA1 = "96f42a9fad2923281d21eca7ecdd3161d2b61655"

    strings:
	$dir1 = "/dev/watchdog"
	$dir2 = "/dev/misc/watchdog"
        $s1 = "PMMV"
        $s2 = "ZOJFKRA"
        $s3 = "FGDCWNV"
        $s4 = "OMVJGP"
    condition:
        $dir1 and $dir2 and $s1 and $s2 and $s3 and not $s4 

}