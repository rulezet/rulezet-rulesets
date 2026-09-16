rule SetupBDoor {
	meta:
		description = "Webshells Auto-generated - file SetupBDoor.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "41f89e20398368e742eda4a3b45716b6"
		id = "055ff783-fa9f-5037-a3d6-88b58ec1612f"
	strings:
		$s1 = "\\BDoor\\SetupBDoor"
	condition:
		all of them
}