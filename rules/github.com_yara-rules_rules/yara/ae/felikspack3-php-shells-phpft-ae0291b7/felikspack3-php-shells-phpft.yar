rule FeliksPack3___PHP_Shells_phpft {
	meta:
		description = "Webshells Auto-generated - file phpft.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "60ef80175fcc6a879ca57c54226646b1"
	strings:
		$s6 = "PHP Files Thief"
		$s11 = "http://www.4ngel.net"
	condition:
		all of them
}