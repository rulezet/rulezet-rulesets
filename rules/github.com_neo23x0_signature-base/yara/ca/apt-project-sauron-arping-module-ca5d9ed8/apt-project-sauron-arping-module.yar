rule APT_Project_Sauron_arping_module {
	meta:
		description = "Detects strings from arping module - Project Sauron report by Kaspersky"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-08"
		id = "42389511-de92-57cb-9dee-9f829fd5e55a"
	strings:
		$s1 = "Resolve hosts that answer"
		$s2 = "Print only replying Ips"
		$s3 = "Do not display MAC addresses"
	condition:
		all of them
}