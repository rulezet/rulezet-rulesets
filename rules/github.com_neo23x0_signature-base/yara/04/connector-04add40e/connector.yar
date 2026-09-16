rule connector {
	meta:
		description = "Webshells Auto-generated - file connector.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3ba1827fca7be37c8296cd60be9dc884"
		id = "e46026bc-c570-5057-a132-5a459c959a69"
	strings:
		$s2 = "If ( AttackID = BROADCAST_ATTACK )"
		$s4 = "Add UNIQUE ID for victims / zombies"
	condition:
		all of them
}