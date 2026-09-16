rule APT_Project_Sauron_dext_module {
	meta:
		description = "Detects strings from dext module - Project Sauron report by Kaspersky"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-08"
		id = "d69373e0-d6ad-5475-8766-06e865620ed8"
	strings:
		$x1 = "Assemble rows of DNS names back to a single string of data"
		$x2 = "removes checks of DNS names and lengths (during split)"
		$x3 = "Randomize data lengths (length/2 to length)"
		$x4 = "This cruft"
	condition:
		2 of them
}