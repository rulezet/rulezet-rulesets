rule APT_Project_Sauron_basex_module {
	meta:
		description = "Detects strings from basex module - Project Sauron report by Kaspersky"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-08"
		id = "51ef3826-af5c-562b-a1f8-3bf11532ac2d"
	strings:
		$x1 = "64, 64url, 32, 32url or 16."
		$s2 = "Force decoding when input is invalid/corrupt"
		$s3 = "This cruft"
	condition:
		$x1 or 2 of them
}