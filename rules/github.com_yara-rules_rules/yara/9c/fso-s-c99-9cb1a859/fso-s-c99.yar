rule FSO_s_c99 {
	meta:
		description = "Webshells Auto-generated - file c99.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5f9ba02eb081bba2b2434c603af454d0"
	strings:
		$s2 = "\"txt\",\"conf\",\"bat\",\"sh\",\"js\",\"bak\",\"doc\",\"log\",\"sfc\",\"cfg\",\"htacce"
	condition:
		all of them
}