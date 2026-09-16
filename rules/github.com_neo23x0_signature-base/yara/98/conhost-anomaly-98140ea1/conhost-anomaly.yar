rule conhost_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file conhost.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "1bd846aa22b1d63a1f900f6d08d8bfa8082ae4db"
		id = "9803fa1b-bcaf-5451-831b-fc0dc9d711f2"
	strings:
		$s2 = "Console Window Host" fullword wide
	condition:
		filename == "conhost.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}