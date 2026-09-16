rule FSO_s_c99 {
	meta:
		description = "Webshells Auto-generated - file c99.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "5f9ba02eb081bba2b2434c603af454d0"
		id = "0b176370-a5ab-587a-b0e9-ef4fe5c604bd"
	strings:
		$s2 = "\"txt\",\"conf\",\"bat\",\"sh\",\"js\",\"bak\",\"doc\",\"log\",\"sfc\",\"cfg\",\"htacce"
	condition:
		all of them
}