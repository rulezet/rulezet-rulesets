rule xssshell_save {
	meta:
		description = "Webshells Auto-generated - file save.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "865da1b3974e940936fe38e8e1964980"
		id = "f33c7559-e2f7-5223-a0e9-4e1d3bc7f080"
	strings:
		$s4 = "RawCommand = Command & COMMAND_SEPERATOR & Param & COMMAND_SEPERATOR & AttackID"
		$s5 = "VictimID = fm_NStr(Victims(i))"
	condition:
		all of them
}