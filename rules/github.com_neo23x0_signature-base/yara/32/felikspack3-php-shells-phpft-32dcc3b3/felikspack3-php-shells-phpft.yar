rule FeliksPack3___PHP_Shells_phpft {
	meta:
		description = "Webshells Auto-generated - file phpft.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "60ef80175fcc6a879ca57c54226646b1"
		id = "00bc690b-4977-5076-a40a-edd39c37233f"
	strings:
		$s6 = "PHP Files Thief"
		$s11 = "http://www.4ngel.net"
	condition:
		all of them
}