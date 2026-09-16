rule Debug_BDoor {
	meta:
		description = "Webshells Auto-generated - file BDoor.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "e4e8e31dd44beb9320922c5f49739955"
		id = "0938efe7-2b6d-5749-af9a-967cca85defb"
	strings:
		$s1 = "\\BDoor\\"
		$s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
	condition:
		all of them
}