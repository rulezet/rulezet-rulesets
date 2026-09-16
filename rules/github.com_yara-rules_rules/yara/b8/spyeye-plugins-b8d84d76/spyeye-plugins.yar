rule spyeye_plugins : banker
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "SpyEye X.Y Plugins memory"
		date = "2012-05-23" 
		version = "1.0" 
		filetype = "memory"

	strings:
		$a = "webfakes.dll"
		$b = "config.dat"					$c = "collectors.txt"
		$d = "webinjects.txt"
		$e = "screenshots.txt"
		$f = "billinghammer.dll"
		$g = "block.dll"					$h = "bugreport.dll"				$i = "ccgrabber.dll"
		$j = "connector2.dll"
		$k = "creditgrab.dll"
		$l = "customconnector.dll"
		$m = "ffcertgrabber.dll"
		$n = "ftpbc.dll"
		$o = "rdp.dll"						$p = "rt_2_4.dll"
		$q = "socks5.dll"					$r = "spySpread.dll"
		$s = "w2chek4_4.dll"
		$t = "w2chek4_6.dll"
	
	condition:
		any of them
}